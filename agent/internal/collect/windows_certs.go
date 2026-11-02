//go:build windows

package collect

import (
	"crypto/sha1" //nolint:gosec // the thumbprint Windows shows is SHA-1 by definition
	"crypto/x509"
	"encoding/hex"
	"math"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/WetlBocker/toner/agent/internal/report"
)

// winCerts lists the computer's own certificates (Cert:\LocalMachine\My) that end within 90 days or ended within the
// last 30, leaving out the computer's own self-named one, as the script did.
func winCerts(r *report.Report) error {
	storeName, _ := windows.UTF16PtrFromString("MY")
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	now := time.Now()
	out := []report.Cert{}
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil || ctx == nil {
			break
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		cert, perr := x509.ParseCertificate(der)
		if perr != nil {
			continue
		}
		if !(cert.NotAfter.Before(now.AddDate(0, 0, 90)) && cert.NotAfter.After(now.AddDate(0, 0, -30))) {
			continue
		}
		subject := windowsSubject(cert)
		if strings.EqualFold(subject, "CN="+r.Computer) {
			continue
		}
		sum := sha1.Sum(der) //nolint:gosec
		out = append(out, report.Cert{Subject: subject, Days: int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24)), Thumb: strings.ToUpper(hex.EncodeToString(sum[:]))})
	}
	r.Certs = &out
	return nil
}

// windowsSubject renders the subject the way PowerShell shows it ("CN=name, O=org"), nearest-first.
func windowsSubject(c *x509.Certificate) string {
	parts := []string{}
	add := func(key string, vals []string) {
		for _, v := range vals {
			parts = append(parts, key+"="+v)
		}
	}
	add("CN", nonEmpty(c.Subject.CommonName))
	add("OU", c.Subject.OrganizationalUnit)
	add("O", c.Subject.Organization)
	add("L", c.Subject.Locality)
	add("S", c.Subject.Province)
	add("C", c.Subject.Country)
	if len(parts) == 0 {
		return c.Subject.String()
	}
	return strings.Join(parts, ", ")
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
