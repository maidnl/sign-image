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
	"flag"
	"fmt"
	"log"
	"os"
)

// MCUboot Header & Configuration Constants
const (
	ImageMagic       uint32 = 0x96f3b83d
	TlvInfoMagic     uint16 = 0x6907
	TlvKeyHash       uint8  = 0x01
	TlvSha256        uint8  = 0x10
	TlvRsa2048       uint8  = 0x20
	HeaderSize       uint16 = 0x400
	SlotSize         int    = 1540096
)

type ImageVersion struct {
	Major    uint8
	Minor    uint8
	Revision uint16
	BuildNum uint32
}

type ImageHeader struct {
	Magic     uint32
	LoadAddr  uint32
	HdrSize   uint16
	PTLVSize  uint16
	ImageSize uint32
	Flags     uint32
	Version   ImageVersion
	Pad1      uint32
}

func main() {
	var loader_bin_file = flag.String("loader_bin", "", "Path to the binary loader to be used");
	var sketch_bin_file = flag.String("sketch_bin", "", "Path to the binary sketch to be used");
	var pem_file = flag.String("pem_file", "", "Path to the PEM file containg keys");
	var erase_flash_dim = flag.Int("erase_flash_dim", 0, "Minimum erasing flash sector dimension in bytes");

	flag.Parse();

	_ = loader_bin_file;
	_ = sketch_bin_file;
	_ = pem_file;
	_ = erase_flash_dim;

	var loader_bin []byte;
	var sketch_bin []byte;
	var err error;

	/* READING LOADER BINARY FILE */
	if *loader_bin_file != "" {
		fmt.Println("loader bin file defined");
	   loader_bin, err = os.ReadFile(*loader_bin_file);
		if err != nil {
			log.Fatalf("Error reading loader binary file: %v", err)
		}
	} else {
		fmt.Println("loader bin file UNDEFINED");
	}
	
	/* READING LOADER BINARY FILE */
	if *sketch_bin_file != "" {
		fmt.Println("sketch bin file defined");
	   sketch_bin, err = os.ReadFile(*sketch_bin_file);
		if err != nil {
			log.Fatalf("Error reading sketch binary file: %v", err)
		}
	} else {
		fmt.Println("sketch bin file UNDEFINED");
	}

	_ = sketch_bin;

	/* CALCULATING PADDING to the SKETCH */	
	loader_len := len(loader_bin);
	fmt.Println(len(loader_bin));
	fmt.Printf("%d (0x%x)\n",loader_len, loader_len);
	

	/* Calculate padding */
	var padding_len = 0;

	if *erase_flash_dim != 0 {
		padding_len = *erase_flash_dim - (loader_len % *erase_flash_dim);
	}

	align_padding := make([]byte,padding_len);


	sketch_offset := uint32(padding_len + loader_len);
	fmt.Printf("align_padding = %d, total size = %d (0x%x)", len(align_padding), sketch_offset, sketch_offset)

	var fileData []byte;


	if len(fileData) < int(HeaderSize) {
		log.Fatalf("Input file is too small to contain the 0x400 header space")
	}

	// 2. Load and parse the RSA Private Key
	keyFile, err := os.ReadFile("root-rsa-2048.pem")
	if err != nil {
		log.Fatalf("Failed to read key: %v", err)
	}

	block, _ := pem.Decode(keyFile)
	if block == nil {
		log.Fatalf("Failed to parse PEM block")
	}
	
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse RSA key: %v", err)
	}

	// 3. Keep the entire pre-padded binary from Zephyr intact
	imageBytes := make([]byte, len(fileData))
	copy(imageBytes, fileData)

	// 4. Construct the MCUboot Header
	header := ImageHeader{
		Magic:     ImageMagic,
		LoadAddr:  0x0,
		HdrSize:   HeaderSize,
		PTLVSize:  0,
		// ImageSize is Total Size minus the 0x400 header reservation
		ImageSize: uint32(len(imageBytes)) - uint32(HeaderSize), 
		Flags:     0x0, 
		Version: ImageVersion{
			Major:    1,
			Minor:    0,
			Revision: 1,
			BuildNum: 0,
		},
	}

	// 5. Overwrite ONLY the first 32 bytes with the little-endian header
	var headerBuf bytes.Buffer
	err = binary.Write(&headerBuf, binary.LittleEndian, header)
	if err != nil {
		log.Fatalf("Failed to write header: %v", err)
	}
	copy(imageBytes[0:32], headerBuf.Bytes())
   
	var myVar uint32 = 0xAABBCCDD
	var address bytes.Buffer
	err = binary.Write(&address, binary.LittleEndian, myVar)
	if err != nil {
		log.Fatalf("Failed to write header: %v", err)
	}
	
	copy(imageBytes[32:36], address.Bytes())
	// 6. Calculate SHA-256 Hash of the exact byte-for-byte image
	imgHash := sha256.Sum256(imageBytes)

	// 7. Calculate the KEYHASH (SHA-256 of the PKCS#1 DER-encoded Public Key)
	// THIS FIXES THE BOOTUTIL_FIND_KEY FAILURE
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	keyHash := sha256.Sum256(pubKeyBytes)

	// 8. Generate RSA-PSS Signature
	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, imgHash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		log.Fatalf("Failed to sign payload: %v", err)
	}

	// 9. Buffer for final output
	var finalImg bytes.Buffer
	finalImg.Write(imageBytes)
	appendTLVs(&finalImg, keyHash[:], imgHash[:], signature)

	// 10. Size Validation & Save
	totalImageSize := finalImg.Len()
	if totalImageSize > SlotSize {
		log.Fatalf("Error: Final image size (%d) exceeds the defined slot size (%d)!", totalImageSize, SlotSize)
	}

	err = os.WriteFile("zephyr.signed.bin", finalImg.Bytes(), 0644)
	if err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
	
	fmt.Println("Image successfully signed and matched to MCUboot specs!")
}

// appendTLVs handles the exact struct packing required by MCUboot
func appendTLVs(img *bytes.Buffer, keyHash []byte, imgHash []byte, sig []byte) {
	binary.Write(img, binary.LittleEndian, TlvInfoMagic)
	binary.Write(img, binary.LittleEndian, uint16(336))

	// 1. Write SHA256 TLV (Type 0x10)
	binary.Write(img, binary.LittleEndian, TlvSha256)
	binary.Write(img, binary.LittleEndian, uint8(0)) 
	binary.Write(img, binary.LittleEndian, uint16(len(imgHash)))
	img.Write(imgHash)

	// 2. Write KeyHash TLV (Type 0x01)
	binary.Write(img, binary.LittleEndian, TlvKeyHash)
	binary.Write(img, binary.LittleEndian, uint8(0)) 
	binary.Write(img, binary.LittleEndian, uint16(len(keyHash)))
	img.Write(keyHash)

	// 3. Write RSA Signature TLV (Type 0x20)
	binary.Write(img, binary.LittleEndian, TlvRsa2048)
	binary.Write(img, binary.LittleEndian, uint8(0)) 
	binary.Write(img, binary.LittleEndian, uint16(len(sig)))
	img.Write(sig)
}
