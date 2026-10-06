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
	"bufio"
	"strings"
	"strconv"
	"path/filepath"
	"regexp"
	"errors"
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

const (
	ConfigPaddingEraseDim = "FLASH_ALIGN_BASED_ON_DT_ERASE_DIM"
	ConfigPaddingCustomDim = "CUSTOM_FLASH_ALIGN_ACTIVE"
)

func GetConfigValue(filePath string, configName string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Ensure clean prefix matching (e.g., CONFIG_FOO=)
	targetConfig := strings.TrimSuffix(configName, "=")
	searchPrefix := targetConfig + "="

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, searchPrefix) {
			// Extract the value after the "="
			value := strings.TrimPrefix(line, searchPrefix)
			
			// Optional: Remove surrounding quotes if it's a string configuration
			value = strings.Trim(value, `"`)
			
			return value, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	// Return an error if the loop finishes without finding the config
	return "", fmt.Errorf("configuration '%s' not found", targetConfig)
}

func HasConfig(filePath string, configName string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Ensure clean prefix matching (e.g., CONFIG_FOO=)
	targetConfig := strings.TrimSuffix(configName, "=")
	searchPrefix := targetConfig + "="

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments (which includes "# CONFIG_XYZ is not set") and empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, searchPrefix) {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// extractNodeBlock finds a labeled DTS node (e.g., slot0_partition: partition@xxx { ... }) 
// and returns the string contents inside its curly braces.
func extractNodeBlock(dtsContent, nodeName string) (string, error) {
   // Match pattern: nodeName: [anything but {] { [capture block] }
   pattern := fmt.Sprintf(`(?s)%s:\s*[^{]*\{([^}]+)\}`, regexp.QuoteMeta(nodeName))
   re := regexp.MustCompile(pattern)
   
   match := re.FindStringSubmatch(dtsContent)
   if len(match) < 2 {
      return "", errors.New("node block not found")
   }
   return match[1], nil
}

func GetPartitionSizes(dtsContent string) (uint32, uint32, error) {
   // 1. Verify boot_partition exists and has the correct label
   bootBlock, err := extractNodeBlock(dtsContent, "boot_partition")
   if err != nil {
      return 0, 0, errors.New("boot_partition not found in DTS")
   }

   labelRegex := regexp.MustCompile(`label\s*=\s*"([^"]+)"`)
   labelMatch := labelRegex.FindStringSubmatch(bootBlock)
   if len(labelMatch) < 2 || labelMatch[1] != "mcuboot" {
      return 0, 0, errors.New("boot_partition does not have the required 'mcuboot' label")
   }

   // 2. Extract and parse slot0_partition
   slot0Block, err := extractNodeBlock(dtsContent, "slot0_partition")
   if err != nil {
      return 0, 0, errors.New("slot0_partition not found in DTS")
   }
   
   slot0Size, err := parseRegSize(slot0Block)
   if err != nil {
      return 0, 0, fmt.Errorf("failed to parse size for slot0_partition: %v", err)
   }

   // 3. Extract and parse slot1_partition (Notice you mentioned slot2_partition in the prompt text, assuming slot1 based on function requirement)
   slot1Block, err := extractNodeBlock(dtsContent, "slot1_partition")
   if err != nil {
      return 0, 0, errors.New("slot1_partition not found in DTS")
   }
   
   slot1Size, err := parseRegSize(slot1Block)
   if err != nil {
      return 0, 0, fmt.Errorf("failed to parse size for slot1_partition: %v", err)
   }

   return slot0Size, slot1Size, nil
}


// parseRegSize extracts the size value from a Zephyr DTS 'reg' property.
// It assumes the standard format: reg = <offset size>;
func parseRegSize(block string) (uint32, error) {
   // Match pattern: reg = < offset size > capturing both hex (0x...) or decimal
   re := regexp.MustCompile(`reg\s*=\s*<\s*(0x[0-9a-fA-F]+|\d+)\s+(0x[0-9a-fA-F]+|\d+)\s*>`)
   match := re.FindStringSubmatch(block)
   
   if len(match) < 3 {
      return 0, errors.New("reg property missing or invalid format")
   }
   
   sizeStr := match[2]
   
   // ParseUint with base 0 automatically handles both '0x' prefixed hex and standard decimal
	rvUint64, err := strconv.ParseUint(sizeStr, 0, 32)

	return uint32(rvUint64), err
}
// ConfigPathFromBin replaces the file extension of the given path with ".config"
func ConfigPathFromBin(binPath string) string {
	// filepath.Ext gets the current extension (e.g., ".bin")
	// strings.TrimSuffix removes it, and we append the new one
	return strings.TrimSuffix(binPath, filepath.Ext(binPath)) + ".config"
}

func DtsPathFromBin(binPath string) string {
	return strings.TrimSuffix(binPath, filepath.Ext(binPath)) + ".dts"
}

func OutPathFromBin(binPath string) string {
	return strings.TrimSuffix(binPath, filepath.Ext(binPath)) + ".signed.bin"
}

/* 
 *  The loader binary file name zephyr.bin file produced by sysbuild has already
 *  an initial padding of 1024 bytes. 
 *  This is done to have a binary files that is ready for the following signing 
 *  binary phase: a blank MCUboot header is already provided and can simply 
 *  be written with the correct information.
 *  The zephyr.signed.bin file is the zephyr.bin file signed. This means that
 *  the first 32 bytes of the header are written and to the end of the file the 
 *  TLV section containing signature information is added.
 *  Here we use zephyr.bin file (NOT the signed version) to avoid to have also
 *  the additional TLV part in the final Image.
 *  However please note that we do not add the header because a blank one has
 *   been already provided by the sysbuild process.
 *  Depending on CONFIG PARAMETER of the variants the padding is automatically
 *  added 
 */

func main() {
	var loader_bin_file = flag.String("loader_bin", "", "Path to the binary loader to be used, with initial padding, not signed");
	var sketch_bin_file = flag.String("sketch_bin", "", "Path to the binary sketch to be used");
	var pem_file = flag.String("pem_file", "", "Path to the PEM file containg keys");
	var erase_flash_dim = flag.Uint("erase_flash_dim", 0, "Minimum erasing flash sector dimension in bytes");

	var config_file string = "undefined";
	var dts_file string = "undefined";
	var output_file string = "undefined";

	flag.Parse();

	_ = loader_bin_file;
	_ = sketch_bin_file;
	_ = pem_file;
	_ = erase_flash_dim;

	var loader_bin []byte;
	var sketch_bin []byte;
	var err error;

	/*
	 * READING LOADER BINARY FILE
	 * ---------------------------*/
	
	if *loader_bin_file != "" {
		fmt.Println("+++ Loader file (%s) found!", *loader_bin_file);
	   loader_bin, err = os.ReadFile(*loader_bin_file);
		if err != nil {
			log.Fatalf("Error reading loader binary file: %v", err)
		}

		/* 
		 * Gathering config and dts filename from bin one
	    * ----------------------------------------------- */
		config_file = ConfigPathFromBin(*loader_bin_file);
		dts_file = DtsPathFromBin(*loader_bin_file);
		output_file = OutPathFromBin(*loader_bin_file);
	} else {
		log.Fatalf("ERROR: loader bin file UNDEFINED");
	}

	/*
	 * CALCULATING LOADER SIZE
	 * ---------------------------*/
	loader_len := uint32(len(loader_bin));
	fmt.Printf("   >>> Loader size %d (0x%08X)\n",loader_len, loader_len);

	var custom_padding_is_present bool = false;
	var custom_padding_dim string = "1024";

	if config_file != "undefined" {
		fmt.Println("--- Parsing configuration file");
		
		 /*
        * By default the erase padding is added
        */

		/*
		erase_padding_is_present, err := HasConfig(config_file,ConfigPaddingEraseDim)
		if err != nil {
			log.Fatalf("Error: problem during config file parsing")
		}
		_ = erase_padding_is_present;
		*/
      
		/* 
		 * VERIFYING (from configuration) if PADDING was added
		 * --------------------------------------------------- */

		custom_padding_is_present, err = HasConfig(config_file,ConfigPaddingEraseDim)
		if err != nil {
			log.Fatalf("WARNING: problem during config file parsing")
		}
		
		if custom_padding_is_present {
			custom_padding_dim, err = GetConfigValue(config_file,ConfigPaddingEraseDim)
			if err != nil {
				log.Fatalf("WARNING: problem during config file parsing")
			}
		}
	} else {
		fmt.Println("Error: unable to find config file");
	}

	_ = custom_padding_dim;
	
	var slot0_dim uint32 = 0;
	var slot1_dim uint32 = 0;

	if dts_file != "undefined" {
		fmt.Println("--- Parsing dts file");

		dtsBytes, err := os.ReadFile(dts_file)
		if err != nil {
			fmt.Println("WARNING: Unable to read dts file")
		}
		
		slot0_dim, slot1_dim, err = GetPartitionSizes(string(dtsBytes))
		if err != nil {
				fmt.Printf("Validation Error: %v\n", err)
		} else {
			fmt.Printf("   >>> Slot 0 size: %d bytes (0x%X)\n", slot0_dim, slot0_dim)
			fmt.Printf("   >>> Slot 1 size: %d bytes (0x%X)\n", slot1_dim, slot1_dim)
		}
	}

	if slot0_dim != slot1_dim {
		fmt.Println("WARNING: slot1 and slot2 have different sizes");
	}

	/* 
	 * READING SKETCH BINARY FILE
	 * ---------------------------*/
	var sketch_len uint32 = 0;
	if *sketch_bin_file != "" {
		fmt.Println("+++ Sketch file (bin) %s found!", *sketch_bin_file);
	   sketch_bin, err = os.ReadFile(*sketch_bin_file);
		if err != nil {
			log.Fatalf("Error reading sketch binary file: %v", err)
		} else {
			sketch_len = uint32(len(sketch_bin));
		}
	} else {
		fmt.Println("WARNING: sketch bin file not defined");
	}

	fmt.Printf("   >>> sketch len = %d (0x%08X)\n", sketch_len, sketch_len);

	/* 
    * CALCULATING PADDING
    * --------------------*/
	
	/* if no padding is configured OR erase padding is present, in any case
    * we pad with erase_flash_dim alignment (default) */
	//var padding_alignement uint32 = uint32(*erase_flash_dim);

	/* Verify padding algorithm */
	//if custom_padding_is_present {
		//padInt, err := strconv.Atoi(custom_padding_dim);
		//padding_alignement = uint32(padInt);
		//if err != nil {
			//fmt.Println("WARNING: problem while converting to integer:", err)
		//}
	//}
	
	var padding_len uint32 = 0;

	//padding_len = padding_alignement - (loader_len % padding_alignement);

	fmt.Println("--- SUMMARY:");

	fmt.Printf("   >>> padding len = %d (0x%08X)\n", padding_len, padding_len);

	align_padding := make([]byte,padding_len);

	/* 
	 * CALCULATING SKETCH OFFSET
	 * -------------------------*/

	sketch_offset := uint32(padding_len + loader_len);
	fmt.Printf("   >>> sketch offset = %d (0x%x)\n", sketch_offset, sketch_offset)

	
	/* 
	 * Getting total size available
	 * ---------------------------- */

	total_size := loader_len + padding_len + sketch_len;

	fmt.Printf("   >>> total size = %d (0x%08X)\n", total_size, total_size);

	if(total_size > slot0_dim) {
		log.Fatalf("ERROR: Image size greater than slot dimension");
	}

	/* 
	 * MAKE NEW IMAGE
	 * ----------------*/
	
	image := make([]byte,total_size);

	/* COPY LOADER */

	pos := copy(image, loader_bin);

	/* COPY PADDING */

	pos += copy(image[pos:], align_padding);

	/* COPY SKETCH (if present) */
	
	if(sketch_len > 0) { 
		pos += copy(image[pos:], sketch_bin);
	}

	/* LOAD AND PARSE THE PRIVATE KEY */

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

	/* CONSTRUCT IMAGE HEADER */

	header := ImageHeader{
		Magic:     ImageMagic,
		LoadAddr:  0x0,
		HdrSize:   HeaderSize,
		PTLVSize:  0,
		ImageSize: uint32(len(image)) - uint32(HeaderSize), 
		Flags:     0x0, 
		Version: ImageVersion{
			Major:    1,
			Minor:    0,
			Revision: 1,
			BuildNum: 0,
		},
	}

	/* OVERWRITE THE FIRST 32 BYTE OF THE IMAGE WITH THE NEW HEADER */

	var headerBuf bytes.Buffer
	err = binary.Write(&headerBuf, binary.LittleEndian, header)
	if err != nil {
		log.Fatalf("Failed to write header: %v", err)
	}
	copy(image[0:32], headerBuf.Bytes())
  
	/* WRITE INTO THE PADDING THE INFORMATION */
	binary.LittleEndian.PutUint32(image[32:36], sketch_offset)
	binary.LittleEndian.PutUint32(image[36:40], uint32(*erase_flash_dim))
	block_num := (sketch_len / uint32(*erase_flash_dim)) + 1
	binary.LittleEndian.PutUint32(image[40:44], block_num)
	if custom_padding_is_present {
		binary.LittleEndian.PutUint32(image[44:48], 2)
	} else {
		binary.LittleEndian.PutUint32(image[44:48], 1)
	}
	
	/*
	 * CALCULATE THE HASH OF THE WHOLE IMAGE 
*   */

	imgHash := sha256.Sum256(image)

	/* Calculate the KEYHASH (SHA-256 of the PKCS#1 DER-encoded Public Key) */
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	keyHash := sha256.Sum256(pubKeyBytes)

	/* Generate RSA-PSS Signature */
	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, imgHash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		log.Fatalf("Failed to sign payload: %v", err)
	}

	// Buffer for final output
	var finalImg bytes.Buffer
	finalImg.Write(image)
	appendTLVs(&finalImg, keyHash[:], imgHash[:], signature)

	// Size Validation & Save
	totalImageSize := finalImg.Len()
	if totalImageSize > SlotSize {
		log.Fatalf("Error: Final image size (%d) exceeds the defined slot size (%d)!", totalImageSize, SlotSize)
	}

	err = os.WriteFile(output_file, finalImg.Bytes(), 0644)
	if err != nil {
		log.Fatalf("Failed to write output file(%s), error %v",output_file, err)
	}
	
	fmt.Println("   === IMAGE built and signed successfully")
	fmt.Println("   === Output file: %s", output_file)
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
