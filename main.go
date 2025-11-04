// Export-cli is a standalone tool to decrypt/encrypt Thymer exports. Separate
// from thymer-cli with minimal dependencies so people will be able to easily
// build it from source and be assured they can always access their exports now
// and in the future.

// TODO(memory): stream vs read/write binary file during encrypt/decrypt operation

package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func getPassword(promptString string) string {
	fmt.Printf("%s: ", promptString)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	password := string(bytePassword)
	fmt.Println()
	return password
}

func isValidFilename(filename string) bool {
	if len(filename) <= 3 || len(filename) >= 255 {
		return false
	}
	if filename == "README.txt" {
		return true
	}

	var alnumRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

	parts := regexp.MustCompile(`\.`).Split(filename, -1)

	if len(parts) == 1 { // no period, alphanumeric filename
		return alnumRegex.MatchString(filename)
	} else if len(parts) == 2 { // one period, alphanumeric filename ending in .json
		baseName, extension := parts[0], parts[1]
		return alnumRegex.MatchString(baseName) && extension == "json"
	} else { // invalid (multiple periods)
		return false
	}
}

func extractFilesInZip(targetDir string, zipFilePath string) error {
	r, err := zip.OpenReader(zipFilePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if !isValidFilename(f.Name) {
			return fmt.Errorf("invalid filename in zip: %s", f.Name)
		}
		fmt.Printf(" - extracting %s\n", f.Name)
		outputPath := filepath.Join(targetDir, f.Name)
		outFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		if err != nil {
			outFile.Close()
			rc.Close()
			return err
		}

		outFile.Close()
		rc.Close()

	}

	return nil
}

func decryptFile(filePath string, key []byte) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return DecryptSymmetric(content, key)
}

func encryptFile(filePath string, key []byte) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return EncryptSymmetric(content, key, nil)
}

type EncDecOperation int

const (
	Encrypt EncDecOperation = iota
	Decrypt
)

// Walk all binary files in directory root, and either encrypt or decrypt, using the specified key
func walkBlobsInDir(root string, key []byte, operation EncDecOperation) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && !strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".txt") { // binary files only
			var outBytes []byte
			var err error

			switch operation {
			case Encrypt:
				fmt.Printf(" - encrypting %s\n", info.Name())
				outBytes, err = encryptFile(path, key)
			case Decrypt:
				fmt.Printf(" - decrypting %s\n", info.Name())
				outBytes, err = decryptFile(path, key)
			}

			if err != nil {
				return fmt.Errorf("error processing file %s: %v", path, err)
			}

			// Write the processed content back to the original file
			err = os.WriteFile(path, outBytes, 0600)
			if err != nil {
				return fmt.Errorf("failed to write file %s: %w", path, err)
			}
		}
		return nil
	})
}

// zipFiles compresses one or more files into a single zip archive file.
// srcDir is the directory where the files to be zipped are located.
// destZip is the output zip file path.
func zipFiles(srcDir string, destZip string) error {
	// Create a new zip archive.
	zipFile, err := os.Create(destZip)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add files to the zip archive.
	err = filepath.Walk(srcDir, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %q: %v", filePath, err)
		}
		if info.IsDir() {
			return nil // Skip directories.
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		header.Modified = info.ModTime()
		header.Method = zip.Deflate

		zipEntry, err := zipWriter.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("failed to create zip entry for file %s: %w", filePath, err)
		}

		// Open the file to be zipped.
		srcFile, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", filePath, err)
		}
		defer srcFile.Close()

		// Copy the file data to the zip entry.
		if _, err := io.Copy(zipEntry, srcFile); err != nil {
			return fmt.Errorf("failed to write file %s to zip: %w", filePath, err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory %s: %w", srcDir, err)
	}

	return nil
}

// Given a value which is encrypted in sync.js as ENCRYPT(JSON(v)), return the decrypted `v` (of any type, i.e. interface{})
func decryptEncryptedJsonizedValue(encryptedV interface{}, workspaceKeyBytes []byte) (interface{}, error) {
	if vString, ok := encryptedV.(string); ok {

		vBytes, err := Base64ToBytes(vString)
		if err != nil {
			return nil, fmt.Errorf("error base64 decoding operation value: %v", err)
		}

		decryptedValue, err := DecryptSymmetric(vBytes, workspaceKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("error decrypting operation value: %v", err)
		}
		var result interface{}
		err = json.Unmarshal([]byte(decryptedValue), &result)
		if err != nil {
			return nil, fmt.Errorf("error decoding decrypted operation value: %v", err)
		}
		return result, nil
	} else {
		return nil, fmt.Errorf("expecting string value for %v", encryptedV)
	}
}

// Given a value v, return ENCRYPT(JSON(v)), see sync.js encryptOperation
func encryptAndJsonizeValue(V interface{}, workspaceKeyBytes []byte) (string, error) {
	vBytes, err := json.Marshal(V)
	if err != nil {
		return "", err
	}

	encryptedValue, err := EncryptSymmetric(vBytes, workspaceKeyBytes, nil)
	if err != nil {
		return "", fmt.Errorf("error encrypting operation value: %v", err)
	}

	vString := BytesToBase64(encryptedValue)

	return vString, nil
}

func decryptExport(in, out, password string) error {
	_, err := os.Stat(out)
	if !os.IsNotExist(err) {
		return fmt.Errorf("a file or directory already exists in %s", out)
	}

	tempDir, err := os.MkdirTemp("", "exportcli")
	if err != nil {
		return err
	}
	defer func() {
		fmt.Println(" - removing temporary directory", tempDir)
		os.RemoveAll(tempDir)
	}()

	fmt.Printf("Decrypting export %s -> %s\n", in, out)
	fmt.Printf(" - using temporary directory: %s\n", tempDir)

	// - extract export zip
	err = extractFilesInZip(tempDir, in)
	if err != nil {
		return fmt.Errorf("could not extract zip: %v", err)
	}

	// - read meta.json
	fileData, err := os.ReadFile(filepath.Join(tempDir, "meta.json"))
	if err != nil {
		return err
	}

	var metaJson ExportMetaJson
	err = json.Unmarshal(fileData, &metaJson)
	if err != nil {
		return err
	}

	if metaJson.Version != "1" {
		return fmt.Errorf("this export version (%s) is not supported", metaJson.Version)
	}

	// - get workspace key bytes
	workspaceKeyBytes, err := GetWorkspaceKeyBytesFromExportKey(metaJson.Key, password)
	if err != nil {
		return err
	}

	PrintFingerprint(workspaceKeyBytes)

	// - decrypt all blobs
	if err := walkBlobsInDir(tempDir, workspaceKeyBytes, Decrypt); err != nil {
		return err
	}

	// - decrypt operations.json
	fmt.Println(" - decrypting operations.json")
	fileData, err = os.ReadFile(filepath.Join(tempDir, "operations.json"))
	if err != nil {
		return err
	}

	operationJsons := make([]ExportOperationJsonV1, 0)
	err = json.Unmarshal(fileData, &operationJsons)
	if err != nil {
		return err
	}

	for _, operationJson := range operationJsons {
		operationData := operationJson.Data
		for dataKey, dataValue := range operationData {
			if strings.HasPrefix(dataKey, "__") {
				if kvMap, ok := dataValue.(map[string]interface{}); ok {
					// value is a dictionary in which each value is encrypted
					decryptedKvMap := make(map[string]interface{})
					for k, v := range kvMap {
						decryptedValue, err := decryptEncryptedJsonizedValue(v, workspaceKeyBytes)
						if err != nil {
							return err
						}
						decryptedKvMap[k] = decryptedValue
					}
					operationJson.Data[dataKey] = decryptedKvMap
				} else {
					return fmt.Errorf("expecting __ key to be a map")
					/*
						// value is a list of in which each value is encrypted
						if array, ok := result["key3"].([]interface{}); ok {
							isArrayOfStrings := true
							for _, v := range array {
								if _, isString := v.(string); !isString {
									isArrayOfStrings = false
									break
								}
							}
						}
					*/
				}
			} else if strings.HasPrefix(dataKey, "_") {
				decryptedValue, err := decryptEncryptedJsonizedValue(dataValue, workspaceKeyBytes)
				if err != nil {
					return err
				}
				operationJson.Data[dataKey] = decryptedValue
			}
		}
	}

	// - done, write updated operations.json
	newOperationJsonData, err := json.MarshalIndent(&operationJsons, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(tempDir, "operations.json"), newOperationJsonData, 0600)
	if err != nil {
		return fmt.Errorf("error writing operations.json: %v", err)
	}

	fmt.Println(" - updating meta.json")
	// - write updated meta.json
	metaJson.Key.IsEncrypted = false
	metaJson.Key.EncWorkspaceKeyB64 = ""
	metaJson.Key.KDFSalt = ""
	metaJson.Key.KDFCostFactor = 0
	newMetaJsonData, err := json.MarshalIndent(&metaJson, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(tempDir, "meta.json"), newMetaJsonData, 0600)
	if err != nil {
		return fmt.Errorf("error writing meta.json: %v", err)
	}

	fmt.Println(" - creating zip file", out)

	// - zip all files from temporary directory back up
	_, err = os.Stat(out)
	if !os.IsNotExist(err) {
		return fmt.Errorf("a file or directory already exists in %s", out)
	}

	if err := zipFiles(tempDir, out); err != nil {
		return fmt.Errorf("error creating output zip file: %v", err)
	}

	return nil
}

func encryptExport(in, out, password string) error {
	_, err := os.Stat(out)
	if !os.IsNotExist(err) {
		return fmt.Errorf("a file or directory already exists in %s", out)
	}

	tempDir, err := os.MkdirTemp("", "exportcli")
	if err != nil {
		return err
	}
	defer func() {
		fmt.Println(" - removing temporary directory", tempDir)
		os.RemoveAll(tempDir)
	}()

	fmt.Printf("Encrypting export %s -> %s\n", in, out)
	fmt.Printf(" - using temporary directory: %s\n", tempDir)

	// - extract export zip
	err = extractFilesInZip(tempDir, in)
	if err != nil {
		return fmt.Errorf("could not extract zip: %v", err)
	}

	fmt.Println(" - updating meta.json")
	// - read meta.json
	fileData, err := os.ReadFile(filepath.Join(tempDir, "meta.json"))
	if err != nil {
		return err
	}

	var metaJson ExportMetaJson
	err = json.Unmarshal(fileData, &metaJson)
	if err != nil {
		return err
	}

	if metaJson.Version != "1" {
		return fmt.Errorf("this export version (%s) is not supported", metaJson.Version)
	}

	if metaJson.Key.IsEncrypted || metaJson.Key.EncWorkspaceKeyB64 != "" {
		return fmt.Errorf("the export data is already encrypted")
	}

	// - generate a new workspace key
	workspaceKeyBytes, err := GenerateWorkspaceKey()
	if err != nil {
		return err
	}

	PrintFingerprint(workspaceKeyBytes)

	// - encrypt it with user password
	newKeyInfo, err := CreateExportKey(workspaceKeyBytes, metaJson.Key.Author, password)
	if err != nil {
		return err
	}

	metaJson.Key = *newKeyInfo

	// - write updated meta.json
	if !metaJson.Key.IsEncrypted {
		panic("expect encrypted header")
	}
	newMetaJsonData, err := json.MarshalIndent(&metaJson, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(tempDir, "meta.json"), newMetaJsonData, 0600)
	if err != nil {
		return fmt.Errorf("error writing meta.json: %v", err)
	}

	// - encrypt all blobs
	if err := walkBlobsInDir(tempDir, workspaceKeyBytes, Encrypt); err != nil {
		return err
	}

	// - encrypt operations.json
	fmt.Println(" - encrypting operations.json")
	fileData, err = os.ReadFile(filepath.Join(tempDir, "operations.json"))
	if err != nil {
		return err
	}

	operationJsons := make([]ExportOperationJsonV1, 0)
	err = json.Unmarshal(fileData, &operationJsons)
	if err != nil {
		return err
	}

	for _, operationJson := range operationJsons {
		operationData := operationJson.Data
		for dataKey, dataValue := range operationData {
			if strings.HasPrefix(dataKey, "__") {
				if kvMap, ok := dataValue.(map[string]interface{}); ok {
					// value is a dictionary in which each value should be encrypted
					encryptedKvMap := make(map[string]string)
					for k, v := range kvMap {
						encryptedValue, err := encryptAndJsonizeValue(v, workspaceKeyBytes)
						if err != nil {
							return err
						}
						encryptedKvMap[k] = encryptedValue
					}
					operationJson.Data[dataKey] = encryptedKvMap
				} else {
					return fmt.Errorf("expecting __ key to be a map")
					/*
						// value is a list of in which each value is encrypted
						if array, ok := result["key3"].([]interface{}); ok {
							isArrayOfStrings := true
							for _, v := range array {
								if _, isString := v.(string); !isString {
									isArrayOfStrings = false
									break
								}
							}
						}
					*/
				}
			} else if strings.HasPrefix(dataKey, "_") {
				encryptedValue, err := encryptAndJsonizeValue(dataValue, workspaceKeyBytes)
				if err != nil {
					return err
				}
				operationJson.Data[dataKey] = encryptedValue
			}
		}
	}

	// - done, write updated operations.json
	newOperationJsonData, err := json.MarshalIndent(&operationJsons, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(tempDir, "operations.json"), newOperationJsonData, 0600)
	if err != nil {
		return fmt.Errorf("error writing operations.json: %v", err)
	}

	fmt.Println(" - creating zip file", out)

	// - zip all files from temporary directory back up
	_, err = os.Stat(out)
	if !os.IsNotExist(err) {
		return fmt.Errorf("a file or directory already exists in %s", out)
	}

	if err := zipFiles(tempDir, out); err != nil {
		return fmt.Errorf("error creating output zip file: %v", err)
	}

	return nil
}

func main() {
	testMiniCrypto()

	var (
		decrypt  = flag.Bool("decrypt-export", false, "Decrypt export data")
		encrypt  = flag.Bool("encrypt-export", false, "Encrypt export data")
		in       = flag.String("in", "", "Input filename")
		out      = flag.String("out", "", "Outfile filename (should not exist yet)")
		password = flag.String("password", "", "Specify the password for encryption or decryption operation (or leave blank to be prompted)")
	)

	flag.Usage = func() {
		w := flag.CommandLine.Output()

		fmt.Fprintf(w, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()

		fmt.Fprintf(w, "\nExamples: \n")
		fmt.Fprintf(w, "   %s -decrypt-export -in export.zip -out export_decrypted.zip\n", os.Args[0])
		fmt.Fprintf(w, "\nTo rekey export data, first decrypt it, then encrypt it:\n")
		fmt.Fprintf(w, "   %s -decrypt-export -in export.zip -out export_decrypted.zip\n", os.Args[0])
		fmt.Fprintf(w, "   %s -encrypt-export -in export_decrypted.zip -out export_new.zip\n", os.Args[0])
	}

	flag.Parse()

	if (*decrypt && *encrypt) || (!*decrypt && !*encrypt) {
		fmt.Printf("Specify either -decrypt-export or -encrypt-export\n\n")
		flag.Usage()
		return
	}

	if in == nil || out == nil {
		log.Fatalf("Specify input and output file using -in and -out parameter. For example:\n")
		log.Fatalf("%s -decrypt-export -in export.zip -out export2.zip\n", os.Args[0])
	}

	if *decrypt {
		var decryptPassword string
		if password == nil || *password == "" {
			decryptPassword = getPassword(fmt.Sprintf("Enter password to decrypt %s", *in))
		} else {
			decryptPassword = *password
		}
		err := decryptExport(*in, *out, decryptPassword)
		if err != nil {
			log.Fatalf("Failed: %v\n", err)
		}
		fmt.Println(" - done")
		return
	}

	if *encrypt {
		var encryptPassword string
		if password == nil || *password == "" {
			encryptPassword = getPassword(fmt.Sprintf("Enter new password for %s", *out))
			encryptPassword2 := getPassword("Confirm password")
			if encryptPassword2 != encryptPassword {
				log.Fatalf("Passwords don't match")
				return
			}
		} else {
			encryptPassword = *password
		}
		err := encryptExport(*in, *out, encryptPassword)
		if err != nil {
			log.Fatalf("Failed: %v\n", err)
		}
		fmt.Println(" - done")
		return
	}

}
