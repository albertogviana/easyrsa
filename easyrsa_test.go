package easyrsa

import (
	"os"
	"path"
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
	os.Setenv(EasyRSAReqCN, "my-test-cn")
	easyRSA, err := NewEasyRSA()
	e.NoError(err)
	e.Equal(&EasyRSA{BinDir: "/tmp/easy-rsa", KeySize: 2048, CAExpire: 3650}, easyRSA)
	os.Unsetenv(EasyRSABinDir)
	os.Unsetenv(EasyRSAReqCN)
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

func (e *EasyRSATestSuite) Test_InitPKI() {
	os.Setenv(EasyRSABinDir, "/tmp/easy-rsa")
	os.Setenv(EasyRSABatch, "2")
	os.Setenv(EasyRSAReqCN, "my-test-cn")

	dir := "/tmp/easy-rsa-pki"
	os.Mkdir(dir, 0755)
	os.Setenv(EasyRSAPKIDir, dir)

	easyRSA, err := NewEasyRSA()
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "reqs"))
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "private"))
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	os.Unsetenv(EasyRSABinDir)
	os.Unsetenv(EasyRSAPKIDir)
	os.Unsetenv(EasyRSABatch)
	os.Unsetenv(EasyRSAReqCN)
	os.RemoveAll(dir)
}

func (e *EasyRSATestSuite) Test_BuildCA() {
	os.Setenv(EasyRSABinDir, "/tmp/easy-rsa")
	os.Setenv(EasyRSAReqCN, "my-test-cn")

	dir := "/tmp/easy-rsa-pki"
	os.Mkdir(dir, 0755)
	os.Setenv(EasyRSAPKIDir, dir)

	easyRSA, err := NewEasyRSA()
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	err = easyRSA.BuildCA()
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "ca.crt"))
	e.NoError(err)

	os.Unsetenv(EasyRSABinDir)
	os.Unsetenv(EasyRSAPKIDir)
	os.Unsetenv(EasyRSAReqCN)
	os.RemoveAll(dir)
}
