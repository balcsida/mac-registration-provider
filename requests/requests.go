package requests

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"

	"howett.net/plist"

	"github.com/beeper/mac-registration-provider/versions"
)

var client = &http.Client{}

const (
	validationCertURL       = "http://static.ess.apple.com/identity/validation/cert-1.0.plist"
	initializeValidationURL = "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation"
)

type CertResponse struct {
	Cert []byte `plist:"cert"`
}

func makeRequest(ctx context.Context, url string, body, output any) ([]byte, error) {
	method := http.MethodGet
	var bodyReader io.Reader
	if body != nil {
		method = http.MethodPost
		var buf bytes.Buffer
		err := plist.NewEncoder(&buf).Encode(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode body: %w", err)
		}
		bodyReader = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}
	req.Header.Set("User-Agent", versions.Current.UserAgent())
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/x-apple-plist")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		return respData, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return respData, nil
}

func FetchCert(ctx context.Context) ([]byte, error) {
	var parsedResp CertResponse
	respData, err := makeRequest(ctx, validationCertURL, nil, &parsedResp)
	if err != nil {
		return nil, err
	}
	_, err = plist.Unmarshal(respData, &parsedResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	} else if len(parsedResp.Cert) == 0 {
		return nil, fmt.Errorf("didn't get cert in response")
	}
	return parsedResp.Cert, nil
}

type ReqInitializeValidation struct {
	SessionInfoRequest []byte `plist:"session-info-request"`
}

type RespInitializeValidation struct {
	SessionInfo []byte `plist:"session-info"`
	Message     string `plist:"message"`
	Status      int    `plist:"status"`
}

func InitializeValidation(ctx context.Context, request []byte) (sessionInfo []byte, err error) {
	var parsedResp RespInitializeValidation
	var respData []byte
	defer func() {
		if err != nil && respData != nil {
			var rawData map[string]any
			_, plistErr := plist.Unmarshal(respData, &rawData)
			if plistErr == nil {
				log.Printf("Plist response data of errored request: %+v", rawData)
			} else {
				log.Printf("Raw response data of errored request: %s", base64.StdEncoding.EncodeToString(respData))
			}
		}
	}()
	respData, err = makeRequest(ctx, initializeValidationURL, &ReqInitializeValidation{request}, &parsedResp)
	if err != nil {
		return nil, err
	}
	_, err = plist.Unmarshal(respData, &parsedResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	// Handle different response formats
	if len(parsedResp.SessionInfo) > 0 {
		// Standard response with session-info
		sessionInfo = parsedResp.SessionInfo
		return
	} else if parsedResp.Status != 0 && parsedResp.Message != "" {
		// Apple returned a status response (like 5080) with message
		log.Printf("Apple returned status %d with message: %s", parsedResp.Status, parsedResp.Message)
		
		// For status 5080, use the message as session info for the next step
		sessionInfo = []byte(parsedResp.Message)
		return
	} else {
		return nil, fmt.Errorf("didn't get session info in initialize validation response")
	}
	return
}
