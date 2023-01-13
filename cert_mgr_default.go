//go:build !linux && !windows
// +build !linux,!windows

package cert

import (
	"crypto/x509"
)

type DefaultSystemTrustCertMgr struct {
}

func NewSystemTrustCertMgr(certName string) *DefaultSystemTrustCertMgr {
	return &DefaultSystemTrustCertMgr{}
}

func (d *DefaultSystemTrustCertMgr) Install(cert *x509.Certificate) error {
	return UnsupportedSystemError
}

func (d *DefaultSystemTrustCertMgr) List() (*[]*x509.Certificate, error) {
	return nil, UnsupportedSystemError
}

func (d *DefaultSystemTrustCertMgr) Uninstall(cert *x509.Certificate) error {
	return UnsupportedSystemError
}
