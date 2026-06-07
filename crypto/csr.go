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
	// Domains is the list of domain names requested in the CSR.
	Domains []string

	// SubjectCN is the Common Name from the CSR subject.
	SubjectCN string

	// RawBytes is the raw DER-encoded CSR.
	RawBytes []byte
}

// ParseCSR parses a PEM-encoded CSR and returns its information.
// The CSR must be a PKCS#10 certificate signing request.
func ParseCSR(pemData []byte) (*CSRInfo, error) {
	block, rest := pem.Decode(pemData)
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

	info := &CSRInfo{
		Domains:    extractDomains(csr),
		SubjectCN:  csr.Subject.CommonName,
		RawBytes:   pemData,
	}

	return info, nil
}

// ParseCSRFromString parses a CSR from a string (PEM format).
func ParseCSRFromString(csrPEM string) (*CSRInfo, error) {
	return ParseCSR([]byte(csrPEM))
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

	// Add SANs (DNS names)
	for _, name := range csr.DNSNames {
		domains[name] = true
	}

	// Convert map to slice
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}

	return result
}

// ParseCertificate parses a PEM-encoded certificate.
func ParseCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}


