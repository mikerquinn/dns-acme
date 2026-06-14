// Package enroll manages enrollment state and background workers.
package enroll

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hashicorp/go-hclog"
	crt "github.com/mikerquinn/dns-acme/crypto"
	"github.com/mikerquinn/dns-acme/dns"
	"github.com/mikerquinn/dns-acme/storage"
)

const defaultACMEURL = "https://acme-v02.api.letsencrypt.org/directory"

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
	logger   hclog.Logger
	mu       sync.Mutex
	active   map[string]bool
}

// NewIssuer creates a new certificate issuer.
func NewIssuer(store *EnrollmentStorage, registry *dns.ProviderRegistry, logger hclog.Logger) *Issuer {
	return &Issuer{
		store:    store,
		registry: registry,
		logger:   logger,
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
		i.logger.Info("ENROLL: goroutine started", "id", id)

		i.logger.Info("ENROLL: about to get enrollment", "id", id)

		state, err := i.store.GetEnrollment(context.Background(), id)
		i.logger.Info("ENROLL: got enrollment", "id", id, "err", err)
		if err != nil {
			i.logger.Info("ENROLL: failed to get enrollment", "id", id, "err", err)
			return
		}
		i.logger.Info("ENROLL: got enrollment state", "id", id, "state", state.State)

		if state.State != "pending" {
			i.logger.Info("ENROLL: enrollment not pending", "id", id, "state", state.State)
			return
		}

		// Mark as in progress
		state.State = "in_progress"
		state.UpdatedAt = time.Now()
		i.store.UpdateEnrollment(context.Background(), state)

		i.processEnrollment(context.Background(), state)
	}()
}

// processEnrollment performs the ACME DNS-01 challenge for an enrollment.
func (i *Issuer) processEnrollment(ctx context.Context, state *EnrollmentState) {
	i.logger.Info("ENROLL: processEnrollment started", "id", state.ID)
	// Get ACME account info
	acmeEmail := state.ACMEEmail
	if acmeEmail == "" {
			acmeInfo, err := i.store.GetACMEAccount(ctx)
		if err != nil {
			i.logger.Info("ENROLL: failed to get ACME account", "id", state.ID, "err", err)
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to get ACME account: %v", err))
			return
		}
		i.logger.Info("ENROLL: got ACME email", "id", state.ID, "email", acmeInfo.Email)
		acmeEmail = acmeInfo.Email
	}

	// Parse ACME private key
	acmeKeyData, err := i.store.GetACMEKey(ctx)
	if err != nil {
		i.logger.Info("ENROLL: failed to get ACME key", "id", state.ID, "err", err)
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to get ACME key: %v", err))
		return
	}
	i.logger.Info("ENROLL: got ACME key", "id", state.ID, "key_prefix", acmeKeyData[:50], "key_len", len(acmeKeyData))

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
	// Log the public key's modulus (first 40 chars of base64) for debugging
	if rsaPriv, ok := privateKey.(*rsa.PrivateKey); ok {
		i.logger.Info("ENROLL:ACME key pub_n", "id", state.ID, "pub_n_prefix", base64.StdEncoding.EncodeToString(rsaPriv.N.Bytes())[:40])
	}

	// Create ACME client
	acmeURL := state.ACMEURL
	if acmeURL == "" {
		acmeURL = defaultACMEURL
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

	// Load existing URI to preserve it
	existing, _ := i.store.GetACMEAccount(ctx)
	uriStr := ""
	if existing != nil {
		uriStr = existing.URI
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
		// Persist the new account so subsequent enrollments reuse it
		key, _ := i.store.GetACMEKey(ctx)
		uriStr = reg.URI
		i.logger.Info("ENROLL:SetACMEAccount", "id", state.ID, "key_prefix", key[:50], "uri", uriStr)
		i.store.SetACMEAccount(ctx, &storage.ACMEAccount{
			Email: user.GetEmail(),
			Key:   key,
			URL:   acmeURL,
			URI:   uriStr,
		})
	} else {
		// Query succeeded - store the registration URI
		uriStr = reg.URI
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
		if state.Provider == "" {
			i.failEnrollment(ctx, state, fmt.Sprintf("no matching role found for domain(s) %v — no DNS provider configured", state.Domains))
		} else {
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to get DNS provider: %v", err))
		}
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
		i.logger.Info("ENROLL: stripped intermediate certs", "id", state.ID, "bytes", len(rest))
	}
	parsedCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse issued certificate: %v", err))
		return
	}

	// Log the certificate (OpenBao style)
	i.logger.Info("ENROLL: certificate issued", "id", state.ID, "domains", state.Domains, "expires", parsedCert.NotAfter)

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


