package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	cryptoPkg "github.com/openbao/dnsacme/crypto"
	"github.com/openbao/dnsacme/enroll"
	"github.com/openbao/dnsacme/storage"
)


var _ logical.Backend = (*dnsacmeBackend)(nil)

// dnsacmeBackend wraps the Plugin logic as a logical.Backend for OpenBao.
type dnsacmeBackend struct {
	*Plugin
	logger log.Logger
}

// Setup is called once when the backend is mounted.
func (b *dnsacmeBackend) Setup(ctx context.Context, config *logical.BackendConfig) error {
	storageBackend := &openbaoStorageView{storage: config.StorageView}
	b.Init(ctx, storageBackend)
	return nil
}



// Initialize is called after Setup.
func (b *dnsacmeBackend) Initialize(ctx context.Context, req *logical.InitializationRequest) error {
	return nil
}

// Logger returns the backend logger.
func (b *dnsacmeBackend) Logger() log.Logger {
	return b.logger
}

// System returns the system view.
func (b *dnsacmeBackend) System() logical.SystemView {
	return nil
}

// HandleRequest handles incoming requests to the backend.
func (b *dnsacmeBackend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	path := strings.TrimPrefix(req.Path, "/")

	metadata := make(map[string]string)
	if md, ok := req.Headers["X-Entity-Metadata"]; ok {
		for _, s := range md {
			parts := strings.Split(s, ";")
			for _, part := range parts {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					metadata[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
				}
			}
		}
	}

	entityID := ""
	if eid, ok := req.Headers["X-Entity-Id"]; ok && len(eid) > 0 {
		entityID = eid[0]
	}
	domain := ""
	if d, ok := req.Headers["X-Entity-Domain"]; ok && len(d) > 0 {
		domain = d[0]
	}

	bodyMap, _ := req.Data["body"].(string)
	bodyBytes := []byte(bodyMap)
	if bodyBytes == nil {
		bodyBytes = []byte{}
	}
	httpReq := &http.Request{
		Method: string(req.Operation),
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader(bodyBytes)),
	}
	for k, v := range req.Headers {
		httpReq.Header[k] = v
	}

	switch {
	case path == "config/roles":
		switch req.Operation {
		case logical.ListOperation, logical.ReadOperation:
			return b.handleListRolesHTTP(httpReq)
		}
	case strings.HasPrefix(path, "config/roles/"):
		roleName := strings.TrimPrefix(path, "config/roles/")
		switch req.Operation {
		case logical.ReadOperation:
			return b.handleGetRoleHTTP(roleName, httpReq)
		case logical.DeleteOperation:
			return b.handleDeleteRoleHTTP(roleName, httpReq)
		case logical.UpdateOperation:
			return b.handleSetRoleData(roleName, req.Data)
		}
	case path == "config":
		switch req.Operation {
		case logical.ReadOperation:
			return b.handleGetConfigHTTP(httpReq)
		case logical.UpdateOperation:
			return b.handleSetConfigData(req.Data)
		}
	case path == "config/create":
		switch req.Operation {
		case logical.UpdateOperation:
			return b.handleCreateACMEAccountHTTP(ctx, req.Data)
		}
	case path == "enroll/new":
		switch req.Operation {
		case logical.UpdateOperation:
			return b.handleEnrollData(httpReq, req.Data, entityID, domain, metadata)
		}
	case strings.HasPrefix(path, "enroll/retrieve/"):
		id := strings.TrimPrefix(path, "enroll/retrieve/")
		return b.handleRetrieveHTTP(id, httpReq)
	case path == "enroll/retrieve":
		return b.handleRetrieveHTTP("", httpReq)
	case path == "revoke":
		switch req.Operation {
		case logical.UpdateOperation:
			return b.handleRevokeData(req.Data)
		}
	}

	return nil, nil
}

// SpecialPaths returns paths that have special handling (e.g. unauthenticated).
func (b *dnsacmeBackend) SpecialPaths() *logical.Paths {
	return &logical.Paths{
		Unauthenticated: []string{
			"config",
			"config/*",
			"config/create",
			"enroll/new",
			"enroll/retrieve",
			"enroll/retrieve/*",
			"revoke",
		},
	}
}

// Type returns the backend type.
func (b *dnsacmeBackend) Type() logical.BackendType {
	return logical.TypeLogical
}

// Cleanup is called when the backend is unmounted.
func (b *dnsacmeBackend) Cleanup(ctx context.Context) {}

// InvalidateKey is called when a key is invalidated.
func (b *dnsacmeBackend) InvalidateKey(ctx context.Context, key string) {}

// HandleExistenceCheck checks if a key exists.
func (b *dnsacmeBackend) HandleExistenceCheck(ctx context.Context, req *logical.Request) (bool, bool, error) {
	return false, false, nil
}

// openbaoStorageView wraps logical.Storage as StorageBackend
type openbaoStorageView struct {
	storage logical.Storage
}

func (s *openbaoStorageView) Put(ctx context.Context, key string, value []byte) error {
	return s.storage.Put(ctx, &logical.StorageEntry{Key: key, Value: value})
}

func (s *openbaoStorageView) Get(ctx context.Context, key string) ([]byte, error) {
	entry, err := s.storage.Get(ctx, key)
	if err != nil || entry == nil {
		return nil, &storage.NotFoundError{Key: key}
	}
	return entry.Value, nil
}

func (s *openbaoStorageView) Delete(ctx context.Context, key string) error {
	return s.storage.Delete(ctx, key)
}

func (s *openbaoStorageView) List(ctx context.Context, prefix string) ([]string, error) {
	return s.storage.List(ctx, prefix)
}

// --- HTTP helper methods ---

// generateKey creates a new RSA private key and returns it as a PEM-encoded string.
func generateKey() (string, crypto.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal PKCS8 key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemData := pem.EncodeToMemory(block)
	return string(pemData), key, nil
}

func (b *dnsacmeBackend) handleCreateACMEAccountHTTP(ctx context.Context, data map[string]interface{}) (*logical.Response, error) {
	email, _ := data["email"].(string)
	acmeURL, _ := data["acme_url"].(string)
	if email == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "email is required"}}, nil
	}

	// Generate a new RSA private key
	acmeKeyPEM, privateKey, err := generateKey()
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to generate ACME key: " + err.Error()}}, nil
	}

	// Determine ACME server URL
	if acmeURL == "" {
		acmeURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	// Create a temporary ACME user for registration
	user := &acmeUser{email: email, privateKey: privateKey, reg: nil}

	// Create ACME client and register the account
	config := lego.NewConfig(user)
	config.CADirURL = acmeURL
	config.Certificate.KeyType = certcrypto.RSA2048
	config.UserAgent = "openbao-dnsacme-plugin"

	client, err := lego.NewClient(config)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to create ACME client: " + err.Error()}}, nil
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to register ACME account: " + err.Error()}}, nil
	}
	user.SetRegistration(reg)

	// Store the account in config storage
	account := &storage.ACMEAccount{Email: email, Key: acmeKeyPEM}
	if b.configStore != nil {
		if err := b.configStore.SetACMEAccount(ctx, account); err != nil {
			return &logical.Response{Data: map[string]interface{}{"error": "failed to store ACME account: " + err.Error()}}, nil
		}
	}

	// Update plugin's in-memory state
	b.acmeEmail = email
	b.acmeKeyPEM = acmeKeyPEM
	if acmeURL != "" && acmeURL != "https://acme-v02.api.letsencrypt.org/directory" {
		b.acmeURL = acmeURL
	}

	return &logical.Response{Data: map[string]interface{}{
		"message": "ACME account created and registered",
		"email":   email,
		"key":     acmeKeyPEM,
		"uri":     reg.URI,
	}}, nil
}

func (b *dnsacmeBackend) handleSetConfigData(data map[string]interface{}) (*logical.Response, error) {
	email, _ := data["email"].(string)
	key, _ := data["key"].(string)
	acmeURL, _ := data["acme_url"].(string)

	if email == "" || key == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "email and key are required"}}, nil
	}

	if _, err := parseKey([]byte(key)); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "invalid key: " + err.Error()}}, nil
	}

	if b.configStore != nil {
		if err := b.configStore.SetACMEAccount(context.Background(), &storage.ACMEAccount{Email: email, Key: key}); err != nil {
			return &logical.Response{Data: map[string]interface{}{"error": "failed to store ACME account"}}, nil
		}
	}

	b.acmeEmail = email
	b.acmeKeyPEM = key
	if acmeURL != "" {
		b.acmeURL = acmeURL
	}

	return &logical.Response{Data: map[string]interface{}{"message": "ACME account configured", "email": email}}, nil
}

func (b *dnsacmeBackend) handleGetConfigHTTP(r *http.Request) (*logical.Response, error) {
	email := b.acmeEmail
	if email == "" && b.configStore != nil {
		account, err := b.configStore.GetACMEAccount(r.Context())
		if err == nil {
			email = account.Email
		}
	}
	if email == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "ACME account not configured"}}, nil
	}
	return &logical.Response{Data: map[string]interface{}{"email": email}}, nil
}

func (b *dnsacmeBackend) handleListRolesHTTP(r *http.Request) (*logical.Response, error) {
	names, err := b.configStore.ListRoles(r.Context())
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to list roles: " + err.Error()}}, nil
	}
	return &logical.Response{Data: map[string]interface{}{"roles": names}}, nil
}

func (b *dnsacmeBackend) handleGetRoleHTTP(name string, r *http.Request) (*logical.Response, error) {
	role, err := b.configStore.GetRole(r.Context(), name)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "role not found"}}, nil
	}
	return &logical.Response{Data: map[string]interface{}{"role": role}}, nil
}

func (b *dnsacmeBackend) handleDeleteRoleHTTP(name string, r *http.Request) (*logical.Response, error) {
	if err := b.configStore.DeleteRole(r.Context(), name); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to delete role: " + err.Error()}}, nil
	}
	return &logical.Response{Data: map[string]interface{}{"message": "role deleted", "name": name}}, nil
}

func (b *dnsacmeBackend) handleSetRoleData(name string, data map[string]interface{}) (*logical.Response, error) {
	if b.configStore == nil {
		return &logical.Response{Data: map[string]interface{}{"error": "config storage not initialized"}}, nil
	}

	provider, _ := data["provider"].(string)
	allowedNames, _ := data["allowed_names"].(string)

	if provider == "" || allowedNames == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "provider and allowed_names are required"}}, nil
	}

	if err := b.registry.ValidateProvider(provider); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "invalid provider: " + err.Error()}}, nil
	}

	// Extract all remaining keys as credentials
	credentials := make(map[string]interface{})
	for k, v := range data {
		switch k {
		case "provider", "allowed_names", "_",
			"_wrap_ttl", "wrap_info", "wrap_ttl", "token_lookup", "token_policies", "token_no_default_policy",
			"lease_options", "metadata", "data":
		default:
			credentials[k] = v
		}
	}

	role := &storage.DNSRole{Name: name, Provider: provider, Credentials: credentials, AllowedNames: allowedNames}
	if err := b.configStore.SetRole(context.Background(), role); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to store role: " + err.Error()}}, nil
	}
	return &logical.Response{Data: map[string]interface{}{"message": "role configured", "name": name, "provider": role.Provider}}, nil
}

func (b *dnsacmeBackend) handleEnrollData(r *http.Request, data map[string]interface{}, entityID, domain string, metadata map[string]string) (*logical.Response, error) {
	csrStr, _ := data["csr"].(string)
	acmeURL, _ := data["acme_url"].(string)
	acmeEmail, _ := data["acme_email"].(string)

	// Try base64 decode in case it was double-encoded
	if csrStr == "" {
		csrBytes := data["csr"].([]byte)
		if len(csrBytes) > 0 {
			csrStr = string(csrBytes)
		}
	}

	if csrStr == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "CSR is required"}}, nil
	}

	// Try to base64 decode if the CSR looks like base64 (no PEM headers)
	csrPEM := csrStr
	if !strings.Contains(csrStr, "-----") {
		decoded, err := base64.StdEncoding.DecodeString(csrStr)
		if err == nil && len(decoded) > 0 {
			csrPEM = string(decoded)
		}
	}

	csrInfo, err := cryptoPkg.ParseCSRFromString(csrPEM)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "invalid CSR: " + err.Error()}}, nil
	}
	if len(csrInfo.Domains) == 0 {
		return &logical.Response{Data: map[string]interface{}{"error": "CSR has no domain names"}}, nil
	}

	// Validate entity authorization (skip if no entity context, e.g. dev CLI)
	if domain != "" && len(metadata) > 0 {
		if err := b.validateEntityAuthorization(domain, metadata, csrInfo.Domains); err != nil {
			return &logical.Response{Data: map[string]interface{}{"error": "entity not authorized: " + err.Error()}}, nil
		}
	}

	// Find matching role and set provider/credentials
	var matchedProvider string
	var matchedCredentials map[string]interface{}
	roles, _ := b.configStore.ListRoles(context.Background())
	for _, roleName := range roles {
		role, err := b.configStore.GetRole(context.Background(), roleName)
		if err != nil {
			continue
		}
		for _, domainName := range csrInfo.Domains {
			if matchGlob(role.AllowedNames, domainName) {
				matchedProvider = role.Provider
				matchedCredentials = role.Credentials
				break
			}
		}
		if matchedProvider != "" {
			break
		}
	}


	enrollmentID := generateID()
	state := enroll.NewEnrollmentState(enrollmentID, csrPEM, csrInfo.Domains, acmeURL)
	if acmeEmail != "" {
		state.ACMEEmail = acmeEmail
	} else {
		state.ACMEEmail = b.acmeEmail
	}
	state.Provider = matchedProvider
	state.Credentials = matchedCredentials

	if err := b.enrollStore.CreateEnrollment(r.Context(), state); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to create enrollment: " + err.Error()}}, nil
	}

	if b.issuer != nil {
		b.issuer.StartEnrollment(r.Context(), enrollmentID)
	}

	return &logical.Response{Data: map[string]interface{}{
		"id": enrollmentID, "state": "pending", "domains": csrInfo.Domains,
		"message": "enrollment initiated, DNS-01 challenge in progress",
		"retrieve_url": "/enroll/retrieve/" + enrollmentID,
	}}, nil
}

func (b *dnsacmeBackend) handleRetrieveHTTP(id string, r *http.Request) (*logical.Response, error) {
	if id == "" {
		body, err := io.ReadAll(r.Body)
		if err == nil && len(body) > 0 {
			var req struct {
				ID string `json:"id"`
			}
			json.Unmarshal(body, &req)
			id = req.ID
		}
	}
	if id == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "enrollment ID is required"}}, nil
	}
	state, err := b.enrollStore.GetEnrollment(r.Context(), id)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "enrollment not found: " + err.Error()}}, nil
	}
	switch state.State {
	case "pending", "in_progress":
		return &logical.Response{Data: map[string]interface{}{"id": state.ID, "state": state.State, "domains": state.Domains, "message": "enrollment in progress"}}, nil
	case "completed":
		return &logical.Response{Data: map[string]interface{}{"id": state.ID, "state": "completed", "domains": state.Domains, "certificate": state.Certificate, "issued_at": state.UpdatedAt.Format(time.RFC3339), "not_after": state.NotAfter.Format(time.RFC3339), "message": "certificate issued successfully"}}, nil
	case "error":
		return &logical.Response{Data: map[string]interface{}{"id": state.ID, "state": "error", "domains": state.Domains, "error": state.Error}}, nil
	default:
		return &logical.Response{Data: map[string]interface{}{"id": state.ID, "state": state.State, "domains": state.Domains}}, nil
	}
}

func (b *dnsacmeBackend) handleRevokeData(data map[string]interface{}) (*logical.Response, error) {
	certStr, _ := data["certificate"].(string)
	id, _ := data["id"].(string)

	if id != "" {
		state, err := b.enrollStore.GetEnrollment(context.Background(), id)
		if err != nil {
			return &logical.Response{Data: map[string]interface{}{"error": "enrollment not found: " + err.Error()}}, nil
		}
		state.State = "cancelled"
		b.enrollStore.UpdateEnrollment(context.Background(), state)
		return &logical.Response{Data: map[string]interface{}{"id": id, "message": "enrollment cancelled", "domains": state.Domains}}, nil
	}

	if certStr == "" {
		return &logical.Response{Data: map[string]interface{}{"error": "certificate or enrollment id is required"}}, nil
	}

	certParsed, err := cryptoPkg.ParseCertificate([]byte(certStr))
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "invalid certificate: " + err.Error()}}, nil
	}

	key, err := parseKey([]byte(b.acmeKeyPEM))
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to parse ACME key: " + err.Error()}}, nil
	}

	acmeURL := b.acmeURL
	if acmeURL == "" {
		acmeURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	user := &acmeUser{email: b.acmeEmail, privateKey: key, reg: nil}
	config := lego.NewConfig(user)
	config.CADirURL = acmeURL
	config.Certificate.KeyType = "RSA2048"
	config.UserAgent = "openbao-dnsacme-plugin"
	client, err := lego.NewClient(config)
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to create ACME client: " + err.Error()}}, nil
	}

	parsedCert, err := x509.ParseCertificate([]byte(certStr))
	if err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to parse certificate: " + err.Error()}}, nil
	}

	if err := client.Certificate.Revoke(parsedCert.Raw); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "failed to revoke certificate: " + err.Error()}}, nil
	}

	return &logical.Response{Data: map[string]interface{}{"message": "certificate revoked", "serial": certParsed.SerialNumber.String()}}, nil
}

// acmeUser implements registration.User for ACME interactions.
type acmeUser struct {
	email      string
	privateKey crypto.PrivateKey
	reg        *registration.Resource
}

func (u *acmeUser) GetEmail() string              { return u.email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey { return u.privateKey }
func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.reg
}
func (u *acmeUser) SetRegistration(r *registration.Resource) { u.reg = r }

// validateEntityAuthorization checks whether the requesting entity is authorized
// for the requested domains. It uses entity metadata (allowed_domains) or
// DNS provider roles (allowed_names) as the authorization source.
func (b *dnsacmeBackend) validateEntityAuthorization(domain string, metadata map[string]string, domains []string) error {
	b.logger.Info("validateEntityAuthorization", "domains", domains, "metadata", metadata, "configStore", b.configStore != nil)

	if allowedDomains, ok := metadata["allowed_domains"]; ok && allowedDomains != "" {
		allowedList := strings.Split(allowedDomains, ",")
		for _, requested := range domains {
			found := false
			for _, allowed := range allowedList {
				if strings.TrimSpace(allowed) == requested {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("domain %q not in entity's allowed_domains: %s", requested, allowedDomains)
			}
		}
		return nil
	}

	for _, requested := range domains {
		matched := false
		roles, err := b.configStore.ListRoles(context.Background())
		if err != nil {
			b.logger.Warn("could not list roles", "error", err)
			continue
		}
		b.logger.Info("role check", "domain", requested, "roles", roles)

		for _, roleName := range roles {
			role, err := b.configStore.GetRole(context.Background(), roleName)
			if err != nil {
				b.logger.Warn("could not get role", "name", roleName, "error", err)
				continue
			}
			b.logger.Info("checking role", "role", roleName, "allowed", role.AllowedNames, "domain", requested)
			if matchGlob(role.AllowedNames, requested) {
				matched = true
				b.logger.Info("matched", "role", roleName)
				break
			}
		}

		if !matched {
			return fmt.Errorf("domain %q does not match any DNS provider role allowed_names", requested)
		}
	}

	return nil
}

// generateID creates a random hex ID.
func generateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err == nil {
		return hex.EncodeToString(bytes)
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// parseKey parses a PEM-encoded private key.
func parseKey(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "ECDSA PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// matchGlob checks if a domain matches a glob pattern (supports * wildcard and comma-separated patterns).
func matchGlob(pattern, domain string) bool {
	domain = strings.ToLower(domain)

	// Split on comma for comma-separated patterns
	parts := strings.Split(pattern, ",")
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == domain {
			return true
		}
		// Handle wildcard patterns: *.example.com
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // e.g. ".example.com"
			if strings.HasSuffix(domain, suffix) {
				prefix := domain[:len(domain)-len(suffix)]
				// suffix includes the leading dot, so prefix must be non-empty
				// to ensure it's a real subdomain (e.g. "sub" not "")
				if prefix != "" {
					return true
				}
			}
		}
	}

	return false
}
