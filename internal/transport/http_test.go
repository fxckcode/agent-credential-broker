package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendAllowsExplicitLoopbackAndBoundsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("synthetic-response"))
	}))
	defer server.Close()

	response, err := Send(context.Background(), server.URL, http.MethodGet, http.Header{}, nil, time.Second, 1024, true)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != http.StatusOK || response.Body != "synthetic-response" {
		t.Fatalf("response = %+v", response)
	}
	if _, err := Send(context.Background(), server.URL, http.MethodGet, http.Header{}, nil, time.Second, 4, true); err == nil {
		t.Fatal("expected response size limit error")
	}
}

func TestSendRejectsNonHTTPSWithoutExplicitLoopback(t *testing.T) {
	_, err := Send(context.Background(), "http://example.com", http.MethodGet, http.Header{}, nil, time.Second, 1024, false)
	if err == nil || !strings.Contains(err.Error(), "only HTTPS") {
		t.Fatalf("error = %v", err)
	}
}
