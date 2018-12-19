package easyrsa

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
)

// EasyRSABinDir should point to the Easy-RSA top-level dir, where the easyrsa script is located.
const EasyRSABinDir = "EASYRSA_BIN_DIR"

// EasyRSAPKIDir dir to use to hold all PKI-specific files, defaults to $PWD/pki.
const EasyRSAPKIDir = "EASYRSA_PKI_DIR"

// EasyRSABatch enable batch (no-prompt) mode; set env-var to non-zero string to enable
const EasyRSABatch = "EASYRSA_BATCH"

const EasyBin = "easyrsa"

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

func (e *EasyRSA) getCommand() string {
	return path.Join(e.BinDir, EasyBin)
}

// InitPKI initializes a directory for the PKI.
func (e *EasyRSA) InitPKI() error {
	_, privateErr := os.Stat(path.Join(os.Getenv(EasyRSAPKIDir), "private"))
	_, reqsErr := os.Stat(path.Join(os.Getenv(EasyRSAPKIDir), "reqs"))

	if privateErr == nil && reqsErr == nil {
		return nil
	}

	return e.run(e.getCommand(), "init-pki")
}

func (e *EasyRSA) getEnvironmentVariable() []string {
	var vars []string

	vars = append(vars, fmt.Sprintf("EASYRSA=%s", e.BinDir))
	vars = append(vars, fmt.Sprintf("EASYRSA_PKI=%s", os.Getenv(EasyRSAPKIDir)))

	easyrsaBatch := "1"
	if os.Getenv(EasyRSABatch) != "" {
		easyrsaBatch = os.Getenv(EasyRSABatch)
	}

	vars = append(vars, fmt.Sprintf("EASYRSA_BATCH=%s", easyrsaBatch))

	return vars
}

func (e *EasyRSA) run(command string, args ...string) error {
	environment := e.getEnvironmentVariable()

	cmd := exec.Command(command, args...)
	cmd.Env = append(os.Environ(), environment...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func checkPath() error {
	if _, err := os.Stat(os.Getenv(EasyRSABinDir)); os.IsNotExist(err) {
		return err
	}

	if _, err := os.Stat(path.Join(os.Getenv(EasyRSABinDir), EasyBin)); os.IsNotExist(err) {
		return err
	}

	return nil
}
