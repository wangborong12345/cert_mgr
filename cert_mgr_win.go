//go:build windows
// +build windows

package cert

import (
	"bytes"
	"crypto/x509"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"unsafe"
)

type WinSystemTrustCertMgr struct {
	certName string
}

func NewSystemTrustCertMgr(certName string) *WinSystemTrustCertMgr {
	return &WinSystemTrustCertMgr{certName: certName}
}
func (mgr *WinSystemTrustCertMgr) Install(ca *x509.Certificate) error {
	certificates, err := mgr.List()
	if err != nil {
		log.Error(err)
		return err
	}

	for _, certificate := range *certificates {
		if bytes.Compare(certificate.Raw, ca.Raw) == 0 {
			return nil
		}
	}

	utf16Ptr, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		log.Error(utf16Ptr)
		return err
	}
	store, err := windows.CertOpenSystemStore(0, utf16Ptr)
	defer windows.CertCloseStore(store, 0)

	if err != nil {
		log.Error(err)
		return err
	}

	var cert *windows.CertContext
	cert, err = windows.CertEnumCertificatesInStore(store, cert)
	if err != nil {
		panic(err)
	}

	leafCtx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, &ca.Raw[0], uint32(len(ca.Raw)))

	err = windows.CertAddCertificateContextToStore(store, leafCtx, windows.CERT_STORE_ADD_USE_EXISTING, nil)
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (mgr *WinSystemTrustCertMgr) OpenStore() (windows.Handle, error) {
	utf16PtrFromString, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		log.Error(err)
		return 0, err
	}
	store, err := windows.CertOpenSystemStore(0, utf16PtrFromString)
	if err != nil {
		log.Error(err)
		return 0, err
	}
	return store, nil
}

const CryptENotFound = 0x80092004

func (mgr *WinSystemTrustCertMgr) List() (*[]*x509.Certificate, error) {

	var certificates []*x509.Certificate
	store, err := mgr.OpenStore()
	if err != nil {
		log.Error(err)
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)
	var cert *windows.CertContext
	for {
		cert, err = windows.CertEnumCertificatesInStore(store, cert)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok {
				if errno == CryptENotFound {
					break
				}
			}
			log.Error(err)
			return nil, err
		}
		if cert == nil {
			break
		}

		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			certificates = append(certificates, c)
		}
	}
	return &certificates, nil
}

func (mgr *WinSystemTrustCertMgr) Uninstall(cert *x509.Certificate) error {

	store, err := mgr.OpenStore()
	if err != nil {
		log.Error(err)
		return err
	}
	defer windows.CertCloseStore(store, 0)
	var certContext *windows.CertContext
	for {
		certContext, err = windows.CertEnumCertificatesInStore(store, certContext)
		if err != nil {
			if errno, ok := err.(windows.Errno); ok {
				if errno == CryptENotFound {
					break
				}
			}
			log.Error(err)
			return err
		}
		if certContext == nil {
			break
		}

		buf := (*[1 << 20]byte)(unsafe.Pointer(certContext.EncodedCert))[:]
		buf2 := make([]byte, certContext.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			if bytes.Compare(c.Raw, cert.Raw) == 0 {
				err := windows.CertDeleteCertificateFromStore(certContext)
				if err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}
