// Package transport talks to Toner's receiver: a TLS client that accepts exactly one certificate (the fingerprint in
// agent.json), enrollment with the sign-up key, the report POST with its reply, and the download of a newer agent. The
// agent only ever opens connections; nothing here listens.
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is what the agent uses for every request to Toner.
type Client struct {
	pin     string // sha256 of the receiver's certificate, lower-case hex
	version string // what X-Toner-Agent says
	http    *http.Client
}

// ErrPin is returned when the server does not present the pinned certificate.
var ErrPin = errors.New("the server's certificate is not the one Toner's package pinned")

// New makes a client pinned to one certificate. proxyURL "" means a direct connection (what the script did: the
// receiver is normally inside the network); set it for an explicit HTTP proxy.
func New(pin, version, proxyURL string, timeout time.Duration) (*Client, error) {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if len(pin) != 64 {
		return nil, errors.New("the pin must be the certificate's SHA-256, 64 hex characters")
	}
	c := &Client{pin: pin, version: version}
	tr := &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			// The chain is not checked against any authority: only the pinned certificate is accepted, so a self-signed
			// certificate Toner made for itself works and a certificate from any CA for the same name does not.
			InsecureSkipVerify:    true, //nolint:gosec // verified by VerifyPeerCertificate below, against the pin
			VerifyPeerCertificate: c.verify,
			MinVersion:            tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       60 * time.Second,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("the proxy address is not valid: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	c.http = &http.Client{Transport: tr, Timeout: timeout + 15*time.Second}
	return c, nil
}

func (c *Client) verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return ErrPin
	}
	sum := sha256.Sum256(rawCerts[0])
	if hex.EncodeToString(sum[:]) != c.pin {
		return ErrPin
	}
	return nil
}

// Fingerprint is the pin a certificate would need: SHA-256 of its DER bytes, lower-case hex.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// Answer is what Toner says back to a report.
type Answer struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Token   string `json:"token,omitempty"`   // a replacement token to save
	Minutes int    `json:"minutes,omitempty"` // a new reporting interval
	Update  bool   `json:"update,omitempty"`  // Toner is newer: fetch the new agent
	Name    string `json:"name,omitempty"`    // enrollment: the inventory name Toner gave this computer
}

// Enroll asks Toner to add this computer, with the package's sign-up key. The answer carries the token.
func (c *Client) Enroll(ctx context.Context, enrollURL, key, computer string) (*Answer, error) {
	body, _ := json.Marshal(map[string]string{"key": key, "computer": computer})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Toner-Agent", c.version)
	ans, code, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("could not sign up with Toner: %w", err)
	}
	if code != http.StatusOK || !ans.OK || ans.Token == "" {
		if ans.Error != "" {
			return nil, fmt.Errorf("Toner did not sign this computer up (HTTP %d): %s", code, ans.Error)
		}
		return nil, fmt.Errorf("Toner did not sign this computer up (HTTP %d)", code)
	}
	return ans, nil
}

// ErrUnknownToken means Toner no longer knows this computer's token: it was revoked, or the computer was removed.
var ErrUnknownToken = errors.New("Toner does not know this computer's token (revoked, or the computer was removed)")

// Report sends one report and returns Toner's answer.
func (c *Client) Report(ctx context.Context, reportURL, token string, report []byte) (*Answer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reportURL, bytes.NewReader(report))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Toner-Agent", c.version)
	ans, code, err := c.do(req)
	if err != nil {
		return nil, err
	}
	switch {
	case code == http.StatusUnauthorized:
		return nil, ErrUnknownToken
	case code != http.StatusOK:
		if ans.Error != "" {
			return nil, fmt.Errorf("Toner refused the report (HTTP %d): %s", code, ans.Error)
		}
		return nil, fmt.Errorf("Toner refused the report (HTTP %d)", code)
	}
	return ans, nil
}

// Download fetches a newer agent binary. Toner names the SHA-256 in a header; a mismatch is an error, and nothing is
// written anywhere by this function (the caller holds the bytes until it has checked them).
func (c *Client) Download(ctx context.Context, downloadURL, token string, maxBytes int64) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Toner-Agent", c.version)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", describe(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", errors.New("Toner has no agent binary for this platform")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("Toner answered HTTP %d to the update request", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) > maxBytes {
		return nil, "", errors.New("the update is larger than expected; not applied")
	}
	want := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Toner-Agent-Sha256")))
	if want == "" {
		return nil, "", errors.New("Toner did not say the update's checksum; not applied")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return nil, "", errors.New("the update's checksum does not match; not applied")
	}
	return data, want, nil
}

func (c *Client) do(req *http.Request) (*Answer, int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, describe(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	ans := &Answer{}
	_ = json.Unmarshal(bytes.TrimPrefix(raw, []byte("\uFEFF")), ans) // a non-JSON body (an error page) leaves the answer empty
	return ans, resp.StatusCode, nil
}

// describe turns the transport's errors into the sentence an administrator can act on.
func describe(err error) error {
	if errors.Is(err, ErrPin) {
		return ErrPin
	}
	var cerr *tls.CertificateVerificationError
	if errors.As(err, &cerr) && errors.Is(cerr.Err, ErrPin) {
		return ErrPin
	}
	s := err.Error()
	if strings.Contains(s, "pinned") {
		return ErrPin
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return fmt.Errorf("no answer from Toner (timed out): %w", err)
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Errorf("could not reach Toner at %s: %v", uerr.URL, uerr.Err)
	}
	return err
}
