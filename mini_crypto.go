package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"encoding/hex"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	SymmetricNonceLength = 24 // 192-bits, length of nonce for XChaCha20-Poly1305
	PasswordMinLength    = 8  // Define your password minimum length
	SymmetricKeyLength   = 32 // 256-bits chapoly key
	PasswordSaltLength   = 16 // 16 bytes scrypt salt
	PublicKeySize        = 32 // NaCl public key size
	PrivateKeySize       = 32 // NaCl private key size
)

var ScryptServerDefaults = struct {
	N int // CPU/Memory cost parameter
	R int // Block size parameter
	P int // Parallelization parameter
}{
	N: 32768,
	R: 8,
	P: 1,
}

const (
	WorkspaceKeyLengthBits = 256
)

func GenerateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateWorkspaceKey() ([]byte, error) {
	return GenerateRandomBytes(WorkspaceKeyLengthBits / 8)
}

func PasswordNormalize(text string) string {
	return strings.TrimSpace(text)
}

func UTF8ToBytes(inputString string) []byte {
	return []byte(inputString)
}

func BytesToHex(inputBytes []byte) string {
	return hex.EncodeToString(inputBytes)
}

func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

func BytesToBase64(byteData []byte) string {
	return base64.StdEncoding.EncodeToString(byteData)
}

func Base64ToBytes(base64Str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64Str)
}

func BytesToUTF8(byteData []byte) string {
	return string(byteData)
}

func DeriveMasterKeyFromPasswordScrypt(password string, salt []byte, N, r, p int) ([]byte, error) {
	password = PasswordNormalize(password)
	if len(password) < PasswordMinLength {
		return nil, fmt.Errorf("password is too short, must be at least %d characters", PasswordMinLength)
	}
	if len(salt) < 16 || isEmptySlice(salt) {
		return nil, fmt.Errorf("salt must be at least 16 bytes")
	}

	return scrypt.Key([]byte(password), salt, N, r, p, SymmetricKeyLength)
}

func isEmptySlice(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func CreateSalt(len uint) ([]byte, error) {
	salt := make([]byte, len)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// if forceNone is nil, a new random nonce is generated automatically
func EncryptSymmetric(data []byte, key []byte, forceNonce []byte) ([]byte, error) {
	nonce := make([]byte, SymmetricNonceLength)
	if forceNonce != nil {
		copy(nonce, forceNonce)
	} else if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	if len(nonce) != SymmetricNonceLength || isEmptySlice(nonce) {
		panic("invalid nonces should never happen")
	}
	if key == nil || len(key) != SymmetricKeyLength || isEmptySlice(key) {
		panic("invalid keys should never happen")
	}

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	ciphertext := cipher.Seal(nil, nonce, data, nil)

	// Return nonce and ciphertext concatenated
	return append(nonce, ciphertext...), nil
}

func DecryptSymmetric(ciphernonce []byte, key []byte) ([]byte, error) {
	if len(ciphernonce) < SymmetricNonceLength {
		return nil, errors.New("ciphernonce too short")
	}

	// Split nonce and ciphertext
	nonce := ciphernonce[:SymmetricNonceLength]
	ciphertext := ciphernonce[SymmetricNonceLength:]

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func CreateExportKey(workspaceKeyBytes []byte, email string, password string) (*ExportKeyJsonV1, error) {
	salt, err := CreateSalt(PasswordSaltLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	kdfIters := ScryptServerDefaults.N
	key, err := DeriveMasterKeyFromPasswordScrypt(password, salt, kdfIters, ScryptServerDefaults.R, ScryptServerDefaults.P)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	cipher, err := EncryptSymmetric(workspaceKeyBytes, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %v", err)
	}

	result := &ExportKeyJsonV1{
		Author:             email,
		EncWorkspaceKeyB64: BytesToBase64(cipher),
		KDFSalt:            BytesToBase64(salt),
		KDFCostFactor:      kdfIters,
		IsEncrypted:        true,
	}
	return result, nil
}

func PrintFingerprint(key []byte) {
	hash := sha256.Sum256(key)
	fingerprint := hex.EncodeToString(hash[:])
	fmt.Println(" - workspace key fingerprint:", fingerprint)
}

func GetWorkspaceKeyBytesFromExportKey(keyDetails ExportKeyJsonV1, password string) ([]byte, error) {
	if !keyDetails.IsEncrypted {
		return nil, fmt.Errorf("not encrypted")
	}
	salt, err := Base64ToBytes(keyDetails.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to get salt: %v", err)
	}
	key, err := DeriveMasterKeyFromPasswordScrypt(password, salt, keyDetails.KDFCostFactor, ScryptServerDefaults.R, ScryptServerDefaults.P)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}
	cipher, err := Base64ToBytes(keyDetails.EncWorkspaceKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %v", err)
	}
	workspaceKeyBytes, err := DecryptSymmetric(cipher, key)
	if err != nil {
		//return nil, fmt.Errorf("failed to decrypt: %v", err)
		return nil, fmt.Errorf("invalid password")
	}
	return workspaceKeyBytes, nil
}

func should(testName string, expr bool) {
	if expr {
		//fmt.Printf("%s: *** PASSED ***\n", testName)
	} else {
		fmt.Printf("%s: *** FAILED ***\n", testName)
		panic("Test failed")
	}
}

func testMiniCrypto() {
	testMessage := "Hello World with emojis 👨🏽‍🚀👩‍👩‍👧👩‍👩‍👧‍👦🧛 and unicode 日本"
	testPassword := "  日本123hunter2👩‍👩‍👧‍👦🧛"
	complexTestMessage := "𝔗𝔥𝔦𝔰 𝔦𝔰 𝔞 𝔱𝔢𝔰𝔱 𝔰𝔱𝔯𝔦𝔫𝔤 𒀸🌍🚀 with emojis 👍😀, accented éèê, Asian characters 漢字, Arabic أبجد, Cyrillic ЯБГД, and modifiers: café, Z͑͗̈́ͣ͌͛͂͑̉͊͠͏̸͟͢a̧͌͂̊ͤ̽ͧ̊̆͋ͮ̊ͥ͛ͦ͟͡͝͠l̵͊͗ͭͬ̓͊̓ͬ͐͒͋̈̇̈́͑̊̍ͦ̚̕͠͝gͭ̍͗̒ͫ̈̏ͣ̔̒͐͗ͦ̈̓ͬ͑͌̈̒̃ͭ̅͘o̴ͩͬͨ̾̂ͫ͊͐͆̓̉͊͑̐̅͐͗ͤ̾̑̈͒̈́͋̐̿ͥͬ͟͟͝"

	testKey := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	testNonce := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24,
	}

	testKey2 := []byte{
		42, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	}
	//testNonce2 := []byte{
	//	42, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	//	17, 18, 19, 20, 21, 22, 23, 24,
	//}
	testWrongKey := []byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	}

	// Test Utils
	should("testKey correct hex bytes", hex.EncodeToString(testKey) == "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	should("testNonce correct hex bytes", hex.EncodeToString(testNonce) == "0102030405060708090a0b0c0d0e0f101112131415161718")
	should("normalize password", PasswordNormalize(testPassword) == "日本123hunter2👩‍👩‍👧‍👦🧛")

	// Test Key Derivation (scrypt + HKDF)
	masterKey, err := DeriveMasterKeyFromPasswordScrypt(testPassword, testNonce, 4, 8, 1)
	if err != nil {
		panic(err)
	}
	should("correct scrypt derived masterKey", hex.EncodeToString(masterKey) == "4dbd0a64fcc1bf927b43079fab987b0e461a8baf302f71d027347aaa9a31fcb9")

	// Test normalizing complex messages OK
	should("complex message source correct", BytesToHex(UTF8ToBytes(complexTestMessage)) == "f09d9497f09d94a5f09d94a6f09d94b020f09d94a6f09d94b020f09d949e20f09d94b1f09d94a2f09d94b0f09d94b120f09d94b0f09d94b1f09d94aff09d94a6f09d94abf09d94a420f09280b8f09f8c8df09f9a80207769746820656d6f6a697320f09f918df09f98802c20616363656e74656420c3a9c3a8c3aa2c20417369616e206368617261637465727320e6bca2e5ad972c2041726162696320d8a3d8a8d8acd8af2c20437972696c6c696320d0afd091d093d0942c20616e64206d6f646966696572733a2063616665cc812c205acd91cd97cd84cda3cd8ccd9bcd82cd91cc89cd8acda0cd8fcd9fcda2ccb861cd8ccd82cc8acda4ccbdcda7cc8acc86cd8bcdaecc8acda5cd9bcda6cd9fcca7cda1cd9dcda06ccd8acd97cc9acdadcdaccc93cd8acc93cdaccd90cd92cd8bcc88cc87cd84cd91cc8acc8dcda6cda0cc95ccb5cd9d67cdadcc8dcd97cc92cdabcc88cc8fcda3cc94cc92cd90cd97cda6cc88cc93cdaccd91cd8ccc88cc92cc83cdadcc85cd986fcda9cdaccda8ccbecc82cdabcd8acd90cd86cc93cc89cd8acd91cc90cc85cd90cd97cda4ccbecc91cc88cd92cd84cd8bcc90ccbfcda5cdacccb4cd9fcd9fcd9d")
	masterKeyComplex, _ := DeriveMasterKeyFromPasswordScrypt(complexTestMessage, testNonce, 4, 8, 1) // low scrypt parameters just for testing
	should("correctly normalize and hash complex unicode", BytesToHex(masterKeyComplex) == "113ddddc6bbc4fc94d3578ff8083d2922b361e2b6cf4bc1dd5f89a33421054ff")

	// Symmetric Encryption Tests
	staticMsgTest := "Static👨🏽‍🚀👩‍👩‍👧👩‍👩‍👧‍👦🧛日本Test"
	staticEncrypted := "KgIDBAUGBwgJCgsMDQ4PEBESExQVFhcY8/eU0tdqy53uF/qH99yFH7PH4EPljIIPr6Q1CULrcx/itg7qP4wgVglWMw/W/m5Ys+0yKO+Sph9blxGtIAAM3/ZxviW0bXtHnpir5Hd72oBjK/bdvMcQ+N/xuTuAKA=="

	staticEncryptedBytes, _ := Base64ToBytes(staticEncrypted)
	decryptedBytes, err := DecryptSymmetric(staticEncryptedBytes, testKey2)
	if err != nil {
		should("static ciphertext vector symmetric decryption correct", false)
		return
	}
	decrypted := BytesToUTF8(decryptedBytes)

	should("static ciphertext vector symmetric decryption correct", decrypted == staticMsgTest)

	data := UTF8ToBytes(testMessage)
	ciphernonce, _ := EncryptSymmetric(data, testKey, testNonce)
	should("correct symmetric xchacha20poly1305 ciphertext", BytesToBase64(ciphernonce) == "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY/b2r4nxiVdoXUh9Ps1cEVhzeL+LvaBjTv4EkxAtKuaJNmZRvkIkcigGsaea1LPPZjRFE/Q4/j0GYobJ5HpG5nFNWBxAgD692UGoK65bzT5wLH/D9tRFZMEejstkYnmVIPaiGKfxtWueqAUggVx18MBt58bkMRS1dFA==")

	decryptedData, _ := DecryptSymmetric(ciphernonce, testKey)
	should("correct symmetric decryption result", BytesToUTF8(decryptedData) == testMessage)

	decryptedDataWrongKey, _ := DecryptSymmetric(ciphernonce, testWrongKey)
	should("successfully fail with wrong key", decryptedDataWrongKey == nil)
}
