package septr

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetHTTP_SkipsLargeResponseScan(t *testing.T) {
	secretsOn := true
	m := NewNetHTTP(&Config{
		Secrets:              &secretsOn,
		StripFields:          []string{"api_key"},
		MaxResponseScanBytes: 512,
	})
	ts := httptest.NewServer(m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"api_key": "sk_live_%s", "filler": "%s"}`,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", strings.Repeat("x", 2048))
	})))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/big")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.Header.Get("X-Septr-Stripped") != "" {
		t.Fatal("oversized response must not be scanned")
	}
	if !strings.Contains(string(body), "sk_live_") {
		t.Fatal("oversized response must pass through untouched")
	}
}
