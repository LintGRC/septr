package septr

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLockedWriter_DefaultsStatusTo200(t *testing.T) {
	lw := &lockedWriter{header: http.Header{}, buf: &bytes.Buffer{}}
	// A handler that writes a body without calling WriteHeader must not
	// leave statusCode at 0 (that caused a WriteHeader(0) panic downstream).
	_, _ = lw.Write([]byte("hello"))
	if lw.statusCode != http.StatusOK {
		t.Fatalf("expected status 200 after body write, got %d", lw.statusCode)
	}
}

func TestLockedWriter_KeepsExplicitStatus(t *testing.T) {
	lw := &lockedWriter{header: http.Header{}, buf: &bytes.Buffer{}}
	lw.WriteHeader(http.StatusNotFound)
	if lw.statusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", lw.statusCode)
	}
	// second WriteHeader must not override
	lw.WriteHeader(http.StatusOK)
	if lw.statusCode != http.StatusNotFound {
		t.Fatalf("WriteHeader called twice must be ignored, got %d", lw.statusCode)
	}
}

func TestLockedWriter_RealResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	lw := &lockedWriter{header: rec.Header(), buf: &bytes.Buffer{}}
	_, _ = lw.Write([]byte("ok"))
	lw.WriteHeader(http.StatusOK)
	rec.WriteHeader(lw.statusCode)
	_, _ = rec.Write(lw.buf.Bytes())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
