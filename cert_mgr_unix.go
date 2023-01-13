//go:build linux
// +build linux

package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	CaSystemRelatedList []*CaSystemRelated
)

type CaSystemRelated struct {
	Path         string
	TrustCommand []string
	Valid        bool
}

func newCaSystemRelated(path string, trustCommand []string) *CaSystemRelated {
	related := CaSystemRelated{
		Path:         path,
		TrustCommand: trustCommand,
	}
	if _, err := exec.LookPath(related.TrustCommand[0]); err == nil && pathExists(related.Path) {
		related.Valid = true
	}
	return &related
}

// https://wiki.archlinux.org/title/User:Grawity/Adding_a_trusted_CA_certificate
func init() {
	CaSystemRelatedList = append(CaSystemRelatedList, newCaSystemRelated("/etc/pki/ca-trust/source/anchors/", []string{"update-ca-trust"}))
	CaSystemRelatedList = append(CaSystemRelatedList, newCaSystemRelated("/usr/local/share/ca-certificates/", []string{"update-ca-certificates"}))
	CaSystemRelatedList = append(CaSystemRelatedList, newCaSystemRelated("/etc/ca-certificates/trust-source/anchors/", []string{"update-ca-trust"}))
}

func getValidCaSystemRelated() *CaSystemRelated {
	// get first
	for _, related := range CaSystemRelatedList {
		if related.Valid {
			return related
		}
	}
	return nil
}

type UnixSystemTrustCertMgr struct {
	validCaSystemRelated *CaSystemRelated
	certName             string
}

func NewSystemTrustCertMgr(certName string) *UnixSystemTrustCertMgr {
	return &UnixSystemTrustCertMgr{validCaSystemRelated: getValidCaSystemRelated(), certName: certName}
}

func (mgr *UnixSystemTrustCertMgr) Install(ca *x509.Certificate) error {
	certificates, err := mgr.List()
	if err != nil {
		return err
	}
	for _, certificate := range *certificates {
		if bytes.Compare(certificate.Raw, ca.Raw) == 0 {
			return nil
		}
	}

	related := mgr.validCaSystemRelated
	path := filepath.Join(related.Path, mgr.certName)
	file, err := os.Create(path)
	if err != nil {
		log.Error(err)
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err != nil {
		log.Error(err)
		return err
	}

	cmd := CommandWithSudo(related.TrustCommand...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(err, string(out))
		return err
	}

	return nil
}

func (mgr *UnixSystemTrustCertMgr) List() (*[]*x509.Certificate, error) {
	related := mgr.validCaSystemRelated
	var certificates []*x509.Certificate
	dir, err := os.ReadDir(related.Path)
	if err != nil {
		log.Error(err)
		return &certificates, err
	}
	for _, f := range dir {
		if f.IsDir() {
			continue
		}
		path := filepath.Join(related.Path, f.Name())
		x509Cert, err := mgr.FindCertificate(path)
		if err != nil {
			log.Error(err)
			continue
		}
		certificates = append(certificates, x509Cert)
	}
	return &certificates, nil
}

func (mgr *UnixSystemTrustCertMgr) FindCertificate(path string) (*x509.Certificate, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	certDERBlock, _ := pem.Decode(file)
	if certDERBlock == nil {
		return nil, NotFoundCertificate
	}
	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return x509Cert, nil
}

func (mgr *UnixSystemTrustCertMgr) Uninstall(cert *x509.Certificate) error {
	related := mgr.validCaSystemRelated
	path := fmt.Sprintf("%s%s", related.Path, mgr.certName)
	certificate, err := mgr.FindCertificate(path)
	if err != nil {
		log.Error(err)
		return err
	}
	if bytes.Compare(certificate.Raw, cert.Raw) == 0 {
		cmd := CommandWithSudo("rm", "-f", path)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Error(err, string(out))
			return err
		}
	}
	return nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func CommandWithSudo(cmd ...string) *exec.Cmd {
	if _, err := exec.LookPath("sudo"); err != nil {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--"}, cmd...)...)
}
