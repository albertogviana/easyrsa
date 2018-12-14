package easyrsa

import (
	"errors"
	"fmt"
	"os"
)

// EasyRSABinDir should point to the Easy-RSA top-level dir, where the easyrsa script is located.
const EasyRSABinDir = "EASYRSA_BIN_DIR"

// EasyRSA struct
type EasyRSA struct {
	BinDir string // Easy-RSA top-level dir, where the easyrsa script is located.
}

// NewEasyRSA returns an instance of EasyRSA
func NewEasyRSA() (*EasyRSA, error) {
	if os.Getenv(EasyRSABinDir) == "" {
		return nil, errors.New("the path to easy-rsa directory was not define")
	}

	checkEasyRSA := checkPath()
	if checkEasyRSA != nil {
		return nil, checkEasyRSA
	}

	easyRSA := &EasyRSA{
		BinDir: os.Getenv(EasyRSABinDir),
	}

	return easyRSA, nil
}

func checkPath() error {
	if _, err := os.Stat(os.Getenv(EasyRSABinDir)); os.IsNotExist(err) {
		return err
	}

	if _, err := os.Stat(fmt.Sprintf("%s/easyrsa", os.Getenv(EasyRSABinDir))); os.IsNotExist(err) {
		return err
	}

	return nil
}
