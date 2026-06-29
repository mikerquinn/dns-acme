// Package crypto provides CSR parsing utilities.
package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// CSRInfo holds information extracted from a CSR.
type CSRInfo struct {
	Domains   []string
	SubjectCN string
	RawBytes  []byte
}

// ParseCSRFromString parses a PEM-encoded CSR and returns its information.
func ParseCSRFromString(csrPEM string) (*CSRInfo, error) {
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Handle multiple PEM blocks (some CSRs may have trailing data)
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected PEM block type 'CERTIFICATE REQUEST', got: %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return &CSRInfo{
		Domains:   extractDomains(csr),
		SubjectCN: csr.Subject.CommonName,
		RawBytes:  []byte(csrPEM),
	}, nil
}

// ParseCSRAsX509 parses a CSR from a string (PEM format) and returns the raw *x509.CertificateRequest.
// This is compatible with lego's certificate.ObtainForCSRRequest.CSR field.
func ParseCSRAsX509(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// extractDomains extracts all domain names from a CSR's Subject and SANs.
func extractDomains(csr *x509.CertificateRequest) []string {
	domains := make(map[string]bool)

	// Add Common Name if present
	if csr.Subject.CommonName != "" {
		domains[strings.ToLower(csr.Subject.CommonName)] = true
	}

	// Add SANs (DNS names) — lowercased for case-insensitive comparison
	for _, name := range csr.DNSNames {
		domains[strings.ToLower(name)] = true
	}

	// Convert map to slice
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}


