package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

// loggingTransport wraps the underlying RoundTripper to dump the full wire-level
// request and response (including body) for maximum visibility.
type loggingTransport struct {
	rt http.RoundTripper
}

func (t loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	dumpReq, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to dump request: %v\n", err)
	} else {
		fmt.Printf("----- Outgoing Request -----\n%s\n", string(dumpReq))
	}

	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	dumpResp, err := httputil.DumpResponse(resp, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to dump response: %v\n", err)
		return resp, nil
	}

	fmt.Printf("----- Incoming Response -----\n%s\n", string(dumpResp))

	// Reset the body so callers can still read it after dumping.
	if resp.Body != nil {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	return resp, nil
}

func main() {
	var (
		insecure bool
		data     string
	)

	flag.BoolVar(&insecure, "insecure", false, "skip TLS certificate verification (INSECURE)")
	flag.StringVar(&data, "d", "", "data to POST (switches method to POST, content-type application/x-www-form-urlencoded)")
	flag.Parse()

	url := "https://example.com"
	if flag.NArg() > 0 {
		url = flag.Arg(0)
	}

	method := http.MethodGet
	var reqBody io.Reader
	if data != "" {
		method = http.MethodPost
		reqBody = strings.NewReader(data)
	}

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			fmt.Printf("[trace] DNS start: %+v\n", info)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			fmt.Printf("[trace] DNS done: %+v\n", info)
		},
		ConnectStart: func(network, addr string) {
			fmt.Printf("[trace] Connect start: %s %s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Printf("[trace] Connect done: %s %s err=%v\n", network, addr, err)
		},
		TLSHandshakeStart: func() {
			fmt.Println("[trace] TLS handshake start")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			fmt.Printf("[trace] TLS handshake done: version=%x cipher=%x serverName=%s resumed=%v err=%v\n",
				state.Version, state.CipherSuite, state.ServerName, state.DidResume, err)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			fmt.Printf("[trace] Connection obtained: reused=%v idle=%v idleTime=%s addr=%v\n",
				info.Reused, info.WasIdle, info.IdleTime, info.Conn.RemoteAddr())
		},
		GotFirstResponseByte: func() {
			fmt.Println("[trace] First response byte received")
		},
	}

	ctx := httptrace.WithClientTrace(context.Background(), trace)
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("User-Agent", "go_test-debug-client/1.0")
	if data != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure, // intended for debugging only
		},
	}

	client := &http.Client{
		Transport: loggingTransport{rt: transport},
		Timeout:   30 * time.Second,
	}

	fmt.Printf("Requesting %s ...\n", url)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("[info] Final status: %s\n", resp.Status)
	if resp.TLS != nil {
		fmt.Printf("[info] TLS details: version=%x cipher=%x negotiatedProtocol=%q serverName=%s alpnProto=%s\n",
			resp.TLS.Version, resp.TLS.CipherSuite, resp.TLS.NegotiatedProtocol, resp.TLS.ServerName, resp.TLS.NegotiatedProtocol)
		for i, cert := range resp.TLS.PeerCertificates {
			fmt.Printf("[info] Peer cert %d: CN=%s NotBefore=%s NotAfter=%s\n", i, cert.Subject.CommonName, cert.NotBefore, cert.NotAfter)
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read body: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("----- Response Body (as text) -----")
	fmt.Println(string(bodyBytes))
}
