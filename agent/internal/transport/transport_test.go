package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// a TLS test server with a self-signed certificate, as Toner's receiver has
func server(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv, Fingerprint(srv.Certificate().Raw)
}

func TestPinAcceptsOnlyTheCertificate(t *testing.T) {
	srv, pin := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("X-Toner-Agent") != "1.0" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "minutes": 7})
	})
	c, err := New(pin, "1.0", "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ans, err := c.Report(context.Background(), srv.URL+"/report", "tok", []byte(`{"computer":"X"}`))
	if err != nil || !ans.OK || ans.Minutes != 7 {
		t.Fatalf("report: %v %+v", err, ans)
	}
	wrong, _ := New("0000000000000000000000000000000000000000000000000000000000000000", "1.0", "", 5*time.Second)
	_, err = wrong.Report(context.Background(), srv.URL+"/report", "tok", []byte(`{}`))
	if !errors.Is(err, ErrPin) {
		t.Fatalf("another pin must be refused with ErrPin, got %v", err)
	}
	_, err = c.Report(context.Background(), srv.URL+"/report", "bad", []byte(`{}`))
	if !errors.Is(err, ErrUnknownToken) {
		t.Fatalf("a 401 is ErrUnknownToken, got %v", err)
	}
}

func TestEnrollAndDownload(t *testing.T) {
	payload := []byte("a new agent")
	sum := sha256.Sum256(payload)
	srv, pin := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/enroll":
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["key"] != "k" || body["computer"] != "PC1" {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "the sign-up key is wrong"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "token": "t1", "name": "PC1"})
		case "/agent/linux-amd64":
			w.Header().Set("X-Toner-Agent-Sha256", hex.EncodeToString(sum[:]))
			w.Write(payload)
		case "/agent/bad":
			w.Header().Set("X-Toner-Agent-Sha256", "00")
			w.Write(payload)
		default:
			w.WriteHeader(404)
		}
	})
	c, _ := New(pin, "1.0", "", 5*time.Second)
	ans, err := c.Enroll(context.Background(), srv.URL+"/enroll", "k", "PC1")
	if err != nil || ans.Token != "t1" {
		t.Fatalf("enroll: %v %+v", err, ans)
	}
	if _, err := c.Enroll(context.Background(), srv.URL+"/enroll", "wrong", "PC1"); err == nil {
		t.Fatal("a wrong key must fail")
	}
	data, got, err := c.Download(context.Background(), srv.URL+"/agent/linux-amd64", "t1", 1<<20)
	if err != nil || string(data) != string(payload) || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("download: %v", err)
	}
	if _, _, err := c.Download(context.Background(), srv.URL+"/agent/bad", "t1", 1<<20); err == nil {
		t.Fatal("a checksum mismatch must fail")
	}
	if _, _, err := c.Download(context.Background(), srv.URL+"/agent/none", "t1", 1<<20); err == nil {
		t.Fatal("a 404 must fail")
	}
}
