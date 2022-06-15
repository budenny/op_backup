package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/term"
)

// 1Password ---------------------------------------------------------------

type Item struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type Items []Item

type ItemField struct {
	Id    string `json:"id"`
	Value string `json:"value"`
}

type ItemFields struct {
	Fields []ItemField `json:"fields"`
}

func parseJson[Out Items | ItemFields](j string) (Out, error) {
	var i Out
	err := json.Unmarshal([]byte(j), &i)
	return i, err
}

func opExec(args ...string) (string, error) {
	out, err := exec.Command("op", args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), err
}

func tryExtractMasterPassword(itemTitle string, itemJson string) string {
	if strings.HasPrefix(itemTitle, "1Password Account") {
		accountFields, err := parseJson[ItemFields](itemJson)
		if err != nil {
			log.Fatal(err)
		}
		for _, field := range accountFields.Fields {
			if field.Id == "password" {
				return field.Value
			}
		}
	}
	return ""
}

func buildBackupJson() (backupJson string, masterPassword string, err error) {
	fetchItems := func() (Items, error) {
		out, err := opExec("item", "list", "--format=json")
		if err != nil {
			return nil, err
		}
		return parseJson[Items](out)
	}

	items, err := fetchItems()
	if err != nil {
		return
	}

	nItems := len(items)
	if nItems == 0 {
		err = errors.New("no items found")
		return
	}

	bar := pb.StartNew(nItems)

	// channel for items to process
	ch := make(chan Item, nItems)

	// channel for results
	res := make(chan string)

	for i := 0; i < 10; i++ {
		go func() {
			for item := range ch {
				out, err := opExec("item", "get", item.ID, "--format=json")
				bar.Increment()
				if err != nil {
					log.Fatal(err)
				}

				// consider guard by mutex
				if masterPassword == "" {
					masterPassword = tryExtractMasterPassword(item.Title, out)
				}

				res <- out
			}
		}()
	}

	// push all items to channel
	for _, item := range items {
		ch <- item
	}

	// collect results
	var results = make([]string, nItems)
	for i := 0; i < nItems; i++ {
		results[i] = strings.TrimRight(<-res, "\n")
	}

	backupJson = "[\n"
	backupJson += strings.Join(results, ",\n")
	backupJson += "\n]"

	close(ch)
	close(res)

	bar.Finish()

	if masterPassword == "" {
		err = errors.New("no master password found")
	}

	return
}

// Encryption ---------------------------------------------------------

func genEncryptionKey(password string) ([]byte, error) {
	keyBytes := []byte(password)
	aes256keySize := 32
	needKeyBytes := aes256keySize - len(keyBytes)
	if needKeyBytes > 0 {
		keyBytes = append(keyBytes, bytes.Repeat([]byte{byte(needKeyBytes)}, needKeyBytes)...)
	}
	return keyBytes, nil
}

func encrypt(plainText []byte, masterPassword string) ([]byte, error) {
	keyBytes, err := genEncryptionKey(masterPassword)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plainText, nil), nil
}

func decrypt(cipherText []byte, masterPassword string) ([]byte, error) {
	keyBytes, err := genEncryptionKey(masterPassword)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}

// Compression ---------------------------------------------------------

func compress(text string) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(text)); err != nil {
		return nil, err
	}

	if err := gz.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func decompress(data []byte) (string, error) {
	b := bytes.NewBuffer(data)
	gz, err := gzip.NewReader(b)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	var out bytes.Buffer
	if _, err := io.Copy(&out, gz); err != nil {
		return "", err
	}
	return out.String(), nil
}

// CLI --------------------------------------------------------------

func cliLoadBackup() error {
	fpath := os.Args[2]
	if fpath == "" {
		return errors.New("no backup file specified")
	}

	cipherText, err := os.ReadFile(fpath)
	if err != nil {
		return err
	}

	fmt.Println("Enter 1Password master password:")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}

	compressed, err := decrypt(cipherText, string(passBytes))
	if err != nil {
		return err
	}

	backup, err := decompress(compressed)
	if err != nil {
		return err
	}
	fmt.Println(backup)
	return nil
}

func cliStoreBackup() error {
	itemsJson, masterPassword, err := buildBackupJson()
	if err != nil {
		return err
	}

	compressed, err := compress(itemsJson)
	if err != nil {
		return err
	}

	cipherText, err := encrypt(compressed, masterPassword)
	if err != nil {
		return err
	}

	ts := time.Now().Format("2006-01-02_15-04-05")
	fName := ts + ".op_backup"

	if err = os.WriteFile(fName, cipherText, 0600); err != nil {
		return err
	}
	fmt.Println(fName)
	return nil
}

// ------------------------------------------------------------------

func main() {
	var command func() error
	if len(os.Args) > 1 && os.Args[1] == "decrypt" {
		command = cliLoadBackup
	} else {
		command = cliStoreBackup
	}

	if err := command(); err != nil {
		log.Fatal(err)
	}
}
