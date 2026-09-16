package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// MCUboot Header Constants
const (
	ImageMagic       uint32 = 0x96f3b83d
	TlvInfoMagic     uint16 = 0x6907
	TlvSha256        uint8  = 0x10
	TlvRsa2048       uint8  = 0x20
	HeaderSize       uint16 = 0x400
)

// ImageVersion represents the version specified via --version 1.0.1+0
type ImageVersion struct {
	Major    uint8
	Minor    uint8
	Revision uint16
	BuildNum uint32
}

// ImageHeader represents the 32-byte MCUboot header
type ImageHeader struct {
	Magic     uint32
	LoadAddr  uint32
	HdrSize   uint16
	PTLVSize  uint16 // Protected TLV size (0 if unused)
	ImageSize uint32 // Size of the payload
	Flags     uint32 // Flags (e.g., overwrite only)
	Version   ImageVersion
	Pad1      uint32
}

func main() {
	arguments := os.Args

	fmt.Println(len(arguments));
	// 1. Load your unsigned binary and private key
	payload, err := os.ReadFile("unsigned_input.bin")
	if err != nil {
		log.Fatalf("Failed to read payload: %v", err)
	}

	keyFile, err := os.ReadFile("root-rsa-2048.pem")
	if err != nil {
		log.Fatalf("Failed to read key: %v", err)
	}

	// 2. Parse the RSA Private Key
	block, _ := pem.Decode(keyFile)
	if block == nil {
		log.Fatalf("Failed to parse PEM block")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse RSA key: %v", err)
	}

	// 3. Construct the Header
	header := ImageHeader{
		Magic:     ImageMagic,
		LoadAddr:  0x0, 
		HdrSize:   HeaderSize,
		PTLVSize:  0,
		ImageSize: uint32(len(payload)),
		Flags:     0x0, // Add explicit flags if required by your board
		Version: ImageVersion{
			Major:    1,
			Minor:    0,
			Revision: 1,
			BuildNum: 0,
		},
	}

	// 4. Buffer to hold the final image
	var img bytes.Buffer

	// Write header as Little Endian
	binary.Write(&img, binary.LittleEndian, header)

	// Pad the rest of the 0x400 header space with 0xFF
	padding := make([]byte, HeaderSize-uint16(img.Len()))
	for i := range padding {
		padding[i] = 0xFF
	}
	img.Write(padding)

	// Write the actual application payload
	img.Write(payload)

	// 5. Calculate SHA-256 Hash of Header + Payload
	hash := sha256.Sum256(img.Bytes())

	// 6. Generate RSA-PSS Signature
	// MCUboot defaults to RSA-PSS for signatures
	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}

	// 7. Append TLV Trailer (Simplified)
	// You must write the TLV Info Header (Magic + Total Size), 
	// followed by the SHA256 TLV (Type, Length, Value), 
	// followed by the Signature TLV (Type, Length, Value).
	appendTLVs(&img, hash[:], signature)

	// 8. Save the signed binary
	err = os.WriteFile("signed_output.bin", img.Bytes(), 0644)
	if err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
	fmt.Println("Image successfully signed and saved!")
}

// appendTLVs handles the trailer struct packing
func appendTLVs(img *bytes.Buffer, hash []byte, sig []byte) {
	// Calculate total TLV size: Header(4) + SHA256(4 + 32) + RSA(4 + 256) = 300 bytes
	binary.Write(img, binary.LittleEndian, TlvInfoMagic)
	binary.Write(img, binary.LittleEndian, uint16(300))

	// Write SHA256 TLV
	binary.Write(img, binary.LittleEndian, TlvSha256)
	binary.Write(img, binary.LittleEndian, uint8(0)) // reserved
	binary.Write(img, binary.LittleEndian, uint16(len(hash)))
	img.Write(hash)

	// Write RSA Signature TLV
	binary.Write(img, binary.LittleEndian, TlvRsa2048)
	binary.Write(img, binary.LittleEndian, uint8(0)) // reserved
	binary.Write(img, binary.LittleEndian, uint16(len(sig)))
	img.Write(sig)
}
