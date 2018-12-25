package easyrsa

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type EasyRSATestSuite struct {
	suite.Suite
}

func TestEasyRSATestSuite(t *testing.T) {
	suite.Run(t, new(EasyRSATestSuite))
}

func (e *EasyRSATestSuite) Test_NewEasyRSA() {
	expectedEasyRSA := &EasyRSA{Config{
		BinDir:     "/tmp/easy-rsa",
		PKIDir:     "/tmp/easy-rsa",
		CommonName: "my-test-cn",
		KeySize:    2048,
		CAExpire:   3650,
	}}

	config := Config{
		BinDir:     "/tmp/easy-rsa",
		PKIDir:     "/tmp/easy-rsa",
		CommonName: "my-test-cn",
	}

	easyRSA, err := NewEasyRSA(config)
	e.NoError(err)
	e.Equal(expectedEasyRSA, easyRSA)
}

func (e *EasyRSATestSuite) Test_NewEasyRSAWithoutBinDir() {
	_, err := NewEasyRSA(Config{})
	e.EqualError(err, "the path to easy-rsa directory was not define")
}

func (e *EasyRSATestSuite) Test_NewEasyRSAWithoutPKIDir() {
	config := Config{
		BinDir: "/tmp/easy-rsa",
	}

	_, err := NewEasyRSA(config)
	e.EqualError(err, "the path to the pki directory was not define")
}

func (e *EasyRSATestSuite) Test_NewEasyRSAWithoutCN() {
	config := Config{
		BinDir: "/tmp/easy-rsa",
		PKIDir: "/tmp/easy-rsa",
	}

	_, err := NewEasyRSA(config)
	e.EqualError(err, "the common name was not define")
}

func (e *EasyRSATestSuite) Test_NewEasyRSAPathDoesNotExists() {
	config := Config{
		BinDir:     "/tmp/easy-rsa-invalid",
		PKIDir:     "/tmp/easy-rsa-invalid",
		CommonName: "my-test-cn",
	}

	_, err := NewEasyRSA(config)
	e.EqualError(err, "stat /tmp/easy-rsa-invalid: no such file or directory")
}

func (e *EasyRSATestSuite) Test_NewEasyRSAScriptDoesNotExists() {
	dir := "/tmp/easy-rsa-without-bin"
	os.Mkdir(dir, 0755)

	config := Config{
		BinDir:     "/tmp/easy-rsa-without-bin",
		PKIDir:     "/tmp/easy-rsa",
		CommonName: "my-test-cn",
	}
	_, err := NewEasyRSA(config)
	e.EqualError(err, "stat /tmp/easy-rsa-without-bin/easyrsa: no such file or directory")
	os.RemoveAll(dir)
}

func (e *EasyRSATestSuite) Test_InitPKI() {
	dir := fmt.Sprintf("/tmp/easy-rsa-pki-%d", time.Now().UnixNano())
	os.Mkdir(dir, 0755)

	config := Config{
		BinDir:     "/tmp/easy-rsa",
		PKIDir:     dir,
		CommonName: "my-test-cn",
	}

	easyRSA, err := NewEasyRSA(config)
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "reqs"))
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "private"))
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	os.RemoveAll(dir)
}

func (e *EasyRSATestSuite) Test_BuildCA() {
	dir := fmt.Sprintf("/tmp/easy-rsa-pki-%d", time.Now().UnixNano())
	os.Mkdir(dir, 0755)

	config := Config{
		BinDir:           "/tmp/easy-rsa",
		PKIDir:           dir,
		CommonName:       "my-test-cn",
		CountryCode:      "BR",
		Province:         "Sao Paulo",
		City:             "Sao Paulo",
		Organization:     "Unit Test",
		Email:            "admin@example.com",
		OrganizationUnit: "Test",
	}

	easyRSA, err := NewEasyRSA(config)
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	err = easyRSA.BuildCA()
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "ca.crt"))
	e.NoError(err)

	os.RemoveAll(dir)
}

func (e *EasyRSATestSuite) Test_GenReq() {
	dir := fmt.Sprintf("/tmp/easy-rsa-pki-%d", time.Now().UnixNano())
	os.Mkdir(dir, 0755)

	config := Config{
		BinDir:           "/tmp/easy-rsa",
		PKIDir:           dir,
		CommonName:       "my-test-cn",
		CountryCode:      "BR",
		Province:         "Sao Paulo",
		City:             "Sao Paulo",
		Organization:     "Unit Test",
		Email:            "admin@example.com",
		OrganizationUnit: "Test",
		ServerName:       "server",
	}

	easyRSA, err := NewEasyRSA(config)
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	err = easyRSA.BuildCA()
	e.NoError(err)

	requestName := "server"
	err = easyRSA.GenReq(requestName)
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "private", "server.key"))
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "reqs", "server.req"))
	e.NoError(err)

	os.RemoveAll(dir)
}

func (e *EasyRSATestSuite) Test_SignReq() {
	dir := fmt.Sprintf("/tmp/easy-rsa-pki-%d", time.Now().UnixNano())
	os.Mkdir(dir, 0755)

	config := Config{
		BinDir:           "/tmp/easy-rsa",
		PKIDir:           dir,
		CommonName:       "my-test-cn",
		CountryCode:      "BR",
		Province:         "Sao Paulo",
		City:             "Sao Paulo",
		Organization:     "Unit Test",
		Email:            "admin@example.com",
		OrganizationUnit: "Test",
		ServerName:       "server",
	}

	easyRSA, err := NewEasyRSA(config)
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	err = easyRSA.BuildCA()
	e.NoError(err)

	requestName := "client1"
	err = easyRSA.GenReq(requestName)
	e.NoError(err)

	err = easyRSA.SignReq("server", requestName)
	e.NoError(err)

	os.RemoveAll(dir)
}

func (e *EasyRSATestSuite) Test_SignReqError() {
	easyRSA, err := NewEasyRSA(Config{})
	err = easyRSA.SignReq("server1", "test")
	e.EqualError(err, "invalid type, please use server or client")
}

func (e *EasyRSATestSuite) Test_ImportReq() {
	dir := fmt.Sprintf("/tmp/easy-rsa-pki-%d", time.Now().UnixNano())
	os.Mkdir(dir, 0755)

	config := Config{
		BinDir:           "/tmp/easy-rsa",
		PKIDir:           dir,
		CommonName:       "my-test-cn",
		CountryCode:      "BR",
		Province:         "Sao Paulo",
		City:             "Sao Paulo",
		Organization:     "Unit Test",
		Email:            "admin@example.com",
		OrganizationUnit: "Test",
		ServerName:       "server",
	}

	easyRSA, err := NewEasyRSA(config)
	e.NoError(err)

	err = easyRSA.InitPKI()
	e.NoError(err)

	err = easyRSA.BuildCA()
	e.NoError(err)

	requestName := "client1"
	err = easyRSA.GenReq(requestName)
	e.NoError(err)

	dir2 := fmt.Sprintf("/tmp/easy-rsa-pki-%d", time.Now().UnixNano())
	os.Mkdir(dir2, 0755)

	config2 := Config{
		BinDir:           "/tmp/easy-rsa",
		PKIDir:           dir2,
		CommonName:       "my-test-cn2",
		CountryCode:      "BR",
		Province:         "Sao Paulo",
		City:             "Sao Paulo",
		Organization:     "Unit Test",
		Email:            "admin@example.com",
		OrganizationUnit: "Test",
		ServerName:       "server",
	}

	easyRSA2, err := NewEasyRSA(config2)
	e.NoError(err)

	err = easyRSA2.InitPKI()
	e.NoError(err)

	err = easyRSA2.BuildCA()
	e.NoError(err)

	err = easyRSA2.ImportReq(path.Join(dir, "reqs", requestName+".req"), requestName)
	e.NoError(err)

	_, err = os.Stat(path.Join(dir, "reqs", requestName+".req"))
	e.NoError(err)

	os.RemoveAll(dir)
	os.RemoveAll(dir2)
}

func (e *EasyRSATestSuite) Test_ImportReqError() {
	easyRSA, err := NewEasyRSA(Config{})
	err = easyRSA.ImportReq("/tmp/invalid", "invalid")
	e.EqualError(err, "stat /tmp/invalid: no such file or directory")
}
