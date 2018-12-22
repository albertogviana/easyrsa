package easyrsa

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
)

// EasyRSABinDir should point to the Easy-RSA top-level dir, where the easyrsa script is located.
const EasyRSABinDir = "EASYRSA_BIN_DIR"

// EasyRSAPKIDir dir to use to hold all PKI-specific files, defaults to $PWD/pki.
const EasyRSAPKIDir = "EASYRSA_PKI_DIR"

// EasyRSABatch enable batch (no-prompt) mode; set env-var to non-zero string to enable
const EasyRSABatch = "EASYRSA_BATCH"

// EasyRSAReqCN allows to change the common name
const EasyRSAReqCN = "EASYRSA_REQ_CN"

// EasyRSAKeySize key size used to generate the key pairs
const EasyRSAKeySize = "EASYRSA_KEY_SIZE"

// EasyRSACAExpire
const EasyRSACAExpire = "EASYRSA_CA_EXPIRE"

const EasyBin = "easyrsa"

// EasyRSA struct
type EasyRSA struct {
	BinDir   string // Easy-RSA top-level dir, where the easyrsa script is located.
	KeySize  int    // Set the keysize in bits to generate
	CAExpire int    // In how many days should the root CA key expire?
}

// NewEasyRSA returns an instance of EasyRSA
func NewEasyRSA() (*EasyRSA, error) {
	if os.Getenv(EasyRSABinDir) == "" {
		return nil, errors.New("the path to easy-rsa directory was not define")
	}

	if os.Getenv(EasyRSAReqCN) == "" {
		return nil, errors.New("the common name was not define")
	}

	var err error

	var keySize int
	keySize = 2048
	if os.Getenv(EasyRSAKeySize) != "" {
		keySize, err = strconv.Atoi(os.Getenv(EasyRSAKeySize))
		if err != nil {
			return nil, err
		}
	}

	var caExpire int
	caExpire = 3650
	if os.Getenv(EasyRSACAExpire) != "" {
		caExpire, err = strconv.Atoi(os.Getenv(EasyRSACAExpire))
		if err != nil {
			return nil, err
		}
	}

	checkEasyRSA := checkPath()
	if checkEasyRSA != nil {
		return nil, checkEasyRSA
	}

	easyRSA := &EasyRSA{
		BinDir:   os.Getenv(EasyRSABinDir),
		KeySize:  keySize,
		CAExpire: caExpire,
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

// BuildCA generates the Certificate Authority (CA)
func (e *EasyRSA) BuildCA() error {
	return e.run(e.getCommand(), "build-ca", "nopass")
}

func (e *EasyRSA) getEnvironmentVariable() []string {
	var vars []string

	vars = append(vars, fmt.Sprintf("EASYRSA=%s", e.BinDir))
	vars = append(vars, fmt.Sprintf("EASYRSA_PKI=%s", os.Getenv(EasyRSAPKIDir)))

	easyrsaBatch := "1"
	if os.Getenv(EasyRSABatch) != "" {
		easyrsaBatch = os.Getenv(EasyRSABatch)
	}

	vars = append(vars, fmt.Sprintf("%s=%s", EasyRSAReqCN, os.Getenv(EasyRSAReqCN)))
	vars = append(vars, fmt.Sprintf("%s=%s", EasyRSABatch, easyrsaBatch))

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
