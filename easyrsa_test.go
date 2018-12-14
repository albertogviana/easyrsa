package easyrsa

import (
	"os"
	"testing"

	"github.com/stretchr/testify/suite"
)

type EasyRSATestSuite struct {
	suite.Suite
}

func TestEasyRSATestSuite(t *testing.T) {
	suite.Run(t, new(EasyRSATestSuite))
}

func (e *EasyRSATestSuite) Test_NewEasyRSA() {
	os.Setenv(EasyRSABinDir, "/tmp/easy-rsa")
	easyRSA, err := NewEasyRSA()
	e.NoError(err)
	e.Equal(&EasyRSA{BinDir: "/tmp/easy-rsa"}, easyRSA)
	os.Unsetenv(EasyRSABinDir)
}

func (e *EasyRSATestSuite) Test_NewEasyRSAWithoutEnv() {
	_, err := NewEasyRSA()
	e.Error(err, "the path to easy-rsa directory was not define")
}

func (e *EasyRSATestSuite) Test_NewEasyRSAPathDoesNotExists() {
	os.Setenv(EasyRSABinDir, "/tmp/easy-rsa-invalid")
	_, err := NewEasyRSA()
	e.Error(err, "stat /tmp/easy-rsa-invalid: no such file or directory")
	os.Unsetenv(EasyRSABinDir)
}

func (e *EasyRSATestSuite) Test_NewEasyRSAScriptDoesNotExists() {
	dir := "/tmp/easy-rsa-without-bin"
	os.Mkdir(dir, 0755)
	os.Setenv(EasyRSABinDir, dir)
	_, err := NewEasyRSA()
	e.Error(err, "stat /tmp/easy-rsa-without-bin/easyrsa: no such file or directory")
	os.Unsetenv(EasyRSABinDir)
	os.RemoveAll(dir)
}
