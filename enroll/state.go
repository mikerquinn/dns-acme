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

// DefaultACMEURL is the Let's Encrypt production directory URL.
const DefaultACMEURL = "https://acme-v02.api.letsencrypt.org/directory"

// acmeUser implements registration.User so lego can manage the ACME account.
type acmeUser struct {
	email      string
	privateKey crypto.PrivateKey
	reg        *registration.Resource
}

func (u *acmeUser) GetEmail() string                          { return u.email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey          { return u.privateKey }
func (u *acmeUser) GetRegistration() *registration.Resource   { return u.reg }
func (u *acmeUser) SetRegistration(r *registration.Resource)  { u.reg = r }
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// EnrollmentState represents the state of a certificate enrollment.
type EnrollmentState struct {
	ID          string                 `json:"id"`
	CSRPEM      string                 `json:"csr_pem"`
	Domains     []string               `json:"domains"`
	RoleName    string                 `json:"role_name,omitempty"`
	State       string                 `json:"state"` // pending, in_progress, completed, error
	Certificate string                 `json:"certificate,omitempty"`
	NotAfter    time.Time              `json:"not_after,omitempty"`
	Error       string                 `json:"error,omitempty"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// NewEnrollmentState creates a new enrollment state with pending status.
func NewEnrollmentState(id, csrPEM string, domains []string) *EnrollmentState {
	return &EnrollmentState{
		ID:        id,
		CSRPEM:    csrPEM,
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
// The enrollment will timeout after 10 minutes.
const enrollmentTimeout = 10 * time.Minute

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

		// Use background context for storage reads — the request context may be cancelled
		// by the time the goroutine executes.
		enrollCtx := context.Background()
		state, err := i.store.GetEnrollment(enrollCtx, id)
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
		i.logger.Info("ENROLL: about to update enrollment to in_progress", "id", id)
		if err := i.store.UpdateEnrollment(enrollCtx, state); err != nil {
			i.logger.Info("ENROLL: failed to update enrollment to in_progress", "id", id, "err", err)
		} else {
			i.logger.Info("ENROLL: updated enrollment to in_progress", "id", id)
		}

		// Use a background context (not request-scoped) with a timeout to prevent
		// goroutine leaks on hung ACME operations, and so storage writes survive
		// after the HTTP request ends.
		enrollCtx, cancel := context.WithTimeout(context.Background(), enrollmentTimeout)
		defer cancel()
		i.processEnrollment(enrollCtx, state)
	}()
}

// processEnrollment performs the ACME DNS-01 challenge for an enrollment.
func (i *Issuer) processEnrollment(ctx context.Context, state *EnrollmentState) {
	i.logger.Info("ENROLL: processEnrollment started", "id", state.ID)

	// Fetch the ACME account from storage (sealed config path)
	acmeInfo, err := i.store.GetACMEAccount(ctx)
	if err != nil {
		i.logger.Info("ENROLL: failed to get ACME account", "id", state.ID, "err", err)
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to get ACME account: %v", err))
		return
	}
	i.logger.Info("ENROLL: got ACME email", "id", state.ID, "email", acmeInfo.Email)
	acmeEmail := acmeInfo.Email
	acmeKeyData := acmeInfo.Key

	// Parse ACME private key
	keyLen := len(acmeKeyData)
	keyPrefix := acmeKeyData[:min(50, keyLen)]
	i.logger.Info("ENROLL: got ACME key", "id", state.ID, "key_prefix", keyPrefix, "key_len", keyLen)

	block, _ := pem.Decode([]byte(acmeKeyData))
	if block == nil {
		i.failEnrollment(ctx, state, "failed to decode ACME PEM block")
		return
	}

	var privateKey crypto.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse PKCS1 RSA key: %v", err))
			return
		}
		privateKey = key
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse EC private key: %v", err))
			return
		}
		privateKey = key
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse PKCS8 private key: %v", err))
			return
		}
		privateKey = key
	default:
		i.failEnrollment(ctx, state, fmt.Sprintf("unsupported ACME key type: %s", block.Type))
		return
	}

	user := &acmeUser{
		email:      acmeEmail,
		privateKey: privateKey,
		reg:        nil,
	}
	// Log the public key's modulus (first 40 chars of base64) for debugging
	if rsaPriv, ok := privateKey.(*rsa.PrivateKey); ok {
		nPrefix := base64.StdEncoding.EncodeToString(rsaPriv.N.Bytes())
		i.logger.Info("ENROLL:ACME key pub_n", "id", state.ID, "pub_n_prefix", nPrefix[:min(40, len(nPrefix))])
	}

	// Create ACME client
	acmeURL := acmeInfo.URL
	if acmeURL == "" {
		acmeURL = DefaultACMEURL
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

	// Load existing URI to preserve it (from state first, then storage as fallback)
	uriStr := ""
	// Try storage for old enrollments that may not have embedded URI
	existing, _ := i.store.GetACMEAccount(ctx)
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
		keyPrefix := key[:min(50, len(key))]
		i.logger.Info("ENROLL:SetACMEAccount", "id", state.ID, "key_prefix", keyPrefix, "uri", uriStr)
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
	i.logger.Info("ENROLL:ACME registration done", "id", state.ID, "uri", uriStr)

	// Fetch the DNS role from storage
	role, err := i.store.GetRole(ctx, state.RoleName)
	if err != nil {
		i.logger.Info("ENROLL:failed to get role", "id", state.ID, "err", err)
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to get role %s: %v", state.RoleName, err))
		return
	}
	if role == nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("role %s not found", state.RoleName))
		return
	}
	i.logger.Info("ENROLL:got role", "id", state.ID, "provider", role.Provider, "zone", role.Zone)

	// Get the DNS provider for this enrollment
	creds := make(map[string]interface{})
	for k, v := range role.Credentials {
		creds[k] = v
	}
	// Pass provider and zone so providers like Cloudflare can resolve the correct zone
	creds["provider"] = role.Provider
	creds["zone"] = role.Zone
	provider, err := i.registry.GetProvider(role.Provider, creds)
	if err != nil {
		i.logger.Info("ENROLL:failed to get DNS provider", "id", state.ID, "err", err, "provider", role.Provider)
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to get DNS provider: %v", err))
		return
	}
	i.logger.Info("ENROLL:got DNS provider", "id", state.ID, "provider", role.Provider)

	// Set up the DNS-01 challenge solver
	challengeProvider := &dns01ProviderWrapper{provider: provider}
	i.logger.Info("ENROLL:setting DNS-01 provider", "id", state.ID)
	if err := client.Challenge.SetDNS01Provider(challengeProvider); err != nil {
		i.logger.Info("ENROLL:failed to set DNS-01 provider", "id", state.ID, "err", err)
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to set DNS-01 challenge provider: %v", err))
		return
	}
	i.logger.Info("ENROLL:DNS-01 provider set", "id", state.ID)

	// Parse the CSR - lego expects *x509.CertificateRequest
	csr, err := crt.ParseCSRAsX509(state.CSRPEM)
	if err != nil {
		i.failEnrollment(ctx, state, fmt.Sprintf("failed to parse CSR: %v", err))
		return
	}
	i.logger.Info("ENROLL:CSR parsed", "id", state.ID, "domains", state.Domains)

	// Obtain certificate using CSR
	i.logger.Info("ENROLL:calling ObtainForCSR", "id", state.ID)
	certRes, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:    csr,
		Bundle: true,
	})
	if err != nil {
		i.logger.Info("ENROLL:ObtainForCSR failed", "id", state.ID, "error", fmt.Sprintf("%v", err))
		i.failEnrollment(ctx, state, fmt.Sprintf("certificate issuance failed: %v", err))
		return
	}
	i.logger.Info("ENROLL:ObtainForCSR succeeded", "id", state.ID, "cert_len", len(certRes.Certificate))

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
	log := hclog.New(&hclog.LoggerOptions{Name: "dns01_present", Level: hclog.Info, Output: hclog.DefaultOutput, JSONFormat: true})
	log.Info("dns01 Present", "domain", domain)
	// Pass domain as-is: lego's Cloudflare provider already calls GetChallengeInfo
	// internally, which builds _acme-challenge.{domain}. Doubling it would produce
	// _acme-challenge._acme-challenge.{domain}.
	err := w.provider.Present(context.Background(), domain, token, keyAuth)
	log.Info("dns01 Present done", "domain", domain, "err", fmt.Sprintf("%v", err))
	return err
}

func (w *dns01ProviderWrapper) CleanUp(domain, token, keyAuth string) error {
	return w.provider.CleanUp(context.Background(), domain, token, keyAuth)
}


