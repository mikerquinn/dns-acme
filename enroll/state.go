// Package enroll manages enrollment state and background workers.
package enroll

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	crt "github.com/openbao/dnsacme/crypto"
	"github.com/openbao/dnsacme/dns"
)

// acmeUser implements registration.User so lego can manage the ACME account.
type acmeUser struct {
	email   string
	privateKey crypto.PrivateKey
	reg       *registration.Resource
}

func (u *acmeUser) GetEmail() string        { return u.email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey { return u.privateKey }
func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.reg
}
func (u *acmeUser) SetRegistration(r *registration.Resource) { u.reg = r }

// EnrollmentState represents the state of a certificate enrollment.
type EnrollmentState struct {
	ID          string                 `json:"id"`
	CSRPEM      string                 `json:"csr_pem"`
	ACMEEmail   string                 `json:"acme_email,omitempty"`
	ACMEURL     string                 `json:"acme_url,omitempty"`
	Domains     []string               `json:"domains"`
	Provider    string                 `json:"provider"`
	Credentials map[string]interface{} `json:"credentials,omitempty"`
	State       string                 `json:"state"` // pending, in_progress, completed, error
	Certificate string                 `json:"certificate,omitempty"`
	NotAfter    time.Time              `json:"not_after,omitempty"`
	Error       string                 `json:"error,omitempty"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// NewEnrollmentState creates a new enrollment state with pending status.
func NewEnrollmentState(id, csrPEM string, domains []string, acmeURL string) *EnrollmentState {
	return &EnrollmentState{
		ID:        id,
		CSRPEM:    csrPEM,
		ACMEURL:   acmeURL,
		Domains:   domains,
		State:     "pending",
		UpdatedAt: time.Now(),
	}
}

// Issuer handles certificate issuance via ACME DNS-01 challenges.
type Issuer struct {
	store    *EnrollmentStorage
	registry *dns.ProviderRegistry
	mu       sync.Mutex
	active   map[string]bool
}

// NewIssuer creates a new certificate issuer.
func NewIssuer(store *EnrollmentStorage, registry *dns.ProviderRegistry) *Issuer {
	return &Issuer{
		store:    store,
		registry: registry,
		active:   make(map[string]bool),
	}
}

// StartEnrollment starts processing a single enrollment asynchronously.
func (i *Issuer) StartEnrollment(ctx context.Context, id string) {
	i.mu.Lock()
	if i.active[id] {
		i.mu.Unlock()
		return
	}
	i.active[id] = true
	i.mu.Unlock()

	go func() {
		defer func() {
			i.mu.Lock()
			delete(i.active, id)
			i.mu.Unlock()
		}()

		state, err := i.store.GetEnrollment(ctx, id)
		if err != nil {
			fmt.Printf("ENROLL: failed to get enrollment %s: %v\n", id, err)
			return
		}

		if state.State != "pending" {
			fmt.Printf("ENROLL: enrollment %s is not pending (state=%s)\n", id, state.State)
			return
		}

		// Mark as in progress
		state.State = "in_progress"
		state.UpdatedAt = time.Now()
		i.store.UpdateEnrollment(ctx, state)

		i.processEnrollment(ctx, state)
	}()
}

// processEnrollment performs the ACME DNS-01 challenge for an enrollment.
func (i *Issuer) processEnrollment(ctx context.Context, state *EnrollmentState) {
	// Get ACME account info
	acmeEmail := state.ACMEEmail
	if acmeEmail == "" {
		acmeInfo, err := i.store.GetACMEAccount(ctx)
		if err != nil {
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to get ACME account: %v", err))
			return
		}
		acmeEmail = acmeInfo.Email
	}

	// Parse ACME private key
	acmeKeyData, err := i.store.GetACMEKey(ctx)
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to get ACME key: %v", err))
		return
	}

	block, _ := pem.Decode([]byte(acmeKeyData))
	if block == nil {
		i.failEnrollment(ctx, state, "failed to decode ACME PEM block")
		return
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1
		key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if parseErr != nil {
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse ACME key: %v", err))
			return
		}
		privateKey = key
	}

	user := &acmeUser{
		email:      acmeEmail,
		privateKey: privateKey,
		reg:        nil,
	}

	// Create ACME client
	acmeURL := state.ACMEURL
	if acmeURL == "" {
		acmeURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	config := lego.NewConfig(user)
	config.CADirURL = acmeURL
	config.Certificate.KeyType = "RSA2048"
	config.UserAgent = "openbao-dnsacme-plugin"
	config.HTTPClient = &http.Client{Timeout: 30 * time.Second}

	client, err := lego.NewClient(config)
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to create lego client: %v", err))
		return
	}

	// Get or register ACME account
	reg, err := client.Registration.QueryRegistration()
	if err != nil {
		// Register new account - no context argument in v4.20
		reg, err = client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to register ACME account: %v", err))
			return
		}
	}
	// Store registration for future use
	user.SetRegistration(reg)

	// Get the DNS provider for this enrollment
	// The credentials map may not include the "provider" key, so add it
	creds := make(map[string]interface{})
	for k, v := range state.Credentials {
		creds[k] = v
	}
	if state.Provider != "" {
		creds["provider"] = state.Provider
	}
	provider, err := i.registry.GetProvider(state.Provider, creds)
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to get DNS provider: %v", err))
		return
	}

	// Set up the DNS-01 challenge solver
	challengeProvider := &dns01ProviderWrapper{provider: provider}
	if err := client.Challenge.SetDNS01Provider(challengeProvider); err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to set DNS-01 challenge provider: %v", err))
		return
	}

	// Parse the CSR - lego expects *x509.CertificateRequest
	csr, err := crt.ParseCSRAsX509(state.CSRPEM)
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse CSR: %v", err))
		return
	}

	// Obtain certificate using CSR
	certRes, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:    csr,
		Bundle: true,
	})
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("certificate issuance failed: %v", err))
		return
	}

	// certRes.Certificate is a PEM bundle (leaf + intermediates). Extract just the leaf.
	leafBlock, rest := pem.Decode(certRes.Certificate)
	if leafBlock == nil {
		i.failEnrollment(ctx, state, "failed to decode leaf certificate PEM")
		return
	}
	if len(rest) > 0 {
		fmt.Printf("ENROLL: stripped %d bytes of intermediate certs\n", len(rest))
	}
	parsedCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse issued certificate: %v", err))
		return
	}

	// Log the certificate (OpenBao style)
	fmt.Printf("ENROLL: certificate issued for domains: %v, expires: %v\n",
		parsedCert.DNSNames, parsedCert.NotAfter)

	// Update enrollment state
	state.State = "completed"
	state.Certificate = string(certRes.Certificate)
	state.NotAfter = parsedCert.NotAfter
	state.UpdatedAt = time.Now()
	i.store.UpdateEnrollment(ctx, state)
}

func (i *Issuer) failEnrollment(ctx context.Context, state *EnrollmentState, errMsg string) {
	state.State = "error"
	state.Error = errMsg
	state.UpdatedAt = time.Now()
	i.store.UpdateEnrollment(ctx, state)
}

// dns01ProviderWrapper adapts our DNS provider to lego's dns01.Provider interface.
type dns01ProviderWrapper struct {
	provider dns.Provider
}

func (w *dns01ProviderWrapper) Present(domain, token, keyAuth string) error {
	// Pass domain as-is: lego's Cloudflare provider already calls GetChallengeInfo
	// internally, which builds _acme-challenge.{domain}. Doubling it would produce
	// _acme-challenge._acme-challenge.{domain}.
	return w.provider.Present(context.Background(), domain, token, keyAuth)
}

func (w *dns01ProviderWrapper) CleanUp(domain, token, keyAuth string) error {
	return w.provider.CleanUp(context.Background(), domain, token, keyAuth)
}


