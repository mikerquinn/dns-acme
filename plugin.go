// Package main implements the OpenBao DNS-01 ACME plugin.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/lego"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/logical"
	pb "github.com/openbao/openbao/sdk/v2/plugin"
	cryptoPkg "github.com/openbao/dnsacme/crypto"
	"github.com/openbao/dnsacme/dns"
	"github.com/openbao/dnsacme/enroll"
	"github.com/openbao/dnsacme/storage"
)

// --- Plugin implementation ---

// Plugin is the main plugin struct containing all state.
type Plugin struct {
	logger hclog.Logger

	// DNS provider registry (generic, supports any lego provider)
	registry *dns.ProviderRegistry

	// Storage backends
	configStore *storage.ConfigStorage
	enrollStore *enroll.EnrollmentStorage

	// ACME state
	acmeEmail  string
	acmeKey    crypto.PrivateKey
	acmeKeyPEM string
	acmeURL    string

	// Issuer
	issuer *enroll.Issuer

	// Lock for ACME operations
	mu sync.Mutex
}

// NewPlugin creates a new plugin instance.
func NewPlugin(logger hclog.Logger) *Plugin {
	return &Plugin{
		logger:   logger,
		registry: dns.NewProviderRegistry(),
	}
}

// Init sets up the plugin with storage and issuer.
func (p *Plugin) Init(ctx context.Context, backend storage.StorageBackend) {
	if backend == nil {
		p.logger.Warn("Init called with nil backend, using memory storage")
		backend = &memoryBackend{}
	}
	p.configStore = storage.NewConfigStorage(backend)
	p.enrollStore = enroll.NewEnrollmentStorage(backend)

	// Try to load ACME account from storage
	account, err := p.configStore.GetACMEAccount(ctx)
	if err == nil {
		p.acmeEmail = account.Email
		p.acmeKeyPEM = account.Key
		p.logger.Info("loaded ACME account from storage")
	}

	p.issuer = enroll.NewIssuer(p.enrollStore, p.registry)
}

// memoryBackend is a minimal in-memory fallback for when OpenBao storage is not yet available.
type memoryBackend struct{}

func (*memoryBackend) Put(ctx context.Context, key string, value []byte) error            { return nil }
func (*memoryBackend) Get(ctx context.Context, key string) ([]byte, error)                { return nil, &storage.NotFoundError{Key: key} }
func (*memoryBackend) Delete(ctx context.Context, key string) error                       { return nil }
func (*memoryBackend) List(ctx context.Context, prefix string) ([]string, error)          { return nil, nil }

// RegisterPaths registers all HTTP routes on the mux.
func (p *Plugin) RegisterPaths(mux *http.ServeMux) {
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		p.handleConfig(w, r)
	})
	mux.HandleFunc("/config/roles", func(w http.ResponseWriter, r *http.Request) {
		p.handleRoles(w, r)
	})
	mux.HandleFunc("/config/roles/", func(w http.ResponseWriter, r *http.Request) {
		p.handleRole(w, r)
	})
	mux.HandleFunc("/enroll/new", func(w http.ResponseWriter, r *http.Request) {
		p.handleEnroll(w, r)
	})
	mux.HandleFunc("/enroll/retrieve", func(w http.ResponseWriter, r *http.Request) {
		p.handleRetrieve(w, r)
	})
	// Catch-all for /enroll/retrieve/{id}
	mux.HandleFunc("/enroll/retrieve/", func(w http.ResponseWriter, r *http.Request) {
		p.handleRetrieve(w, r)
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		p.handleRevoke(w, r)
	})
}

// --- Config endpoints ---

func (p *Plugin) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		p.handleSetConfig(w, r)
	case http.MethodGet:
		p.handleGetConfig(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
	}
}

func (p *Plugin) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "failed to read request body"})
		return
	}

	var req struct {
		Email   string `json:"email"`
		Key     string `json:"key"`
		ACMEURL string `json:"acme_url"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON: " + err.Error()})
		return
	}

	if req.Email == "" || req.Key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "email and key are required"})
		return
	}

	// Validate key format
	parsedKey, err := parseKey([]byte(req.Key))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid key: " + err.Error()})
		return
	}

	account := &storage.ACMEAccount{Email: req.Email, Key: req.Key}
	if p.configStore != nil {
		if err := p.configStore.SetACMEAccount(r.Context(), account); err != nil {
			p.logger.Error("failed to store ACME account", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to store ACME account"})
			return
		}
	}

	p.acmeEmail = req.Email
	p.acmeKeyPEM = req.Key
	p.acmeKey = parsedKey
	if req.ACMEURL != "" {
		p.acmeURL = req.ACMEURL
	}

	p.logger.Info("ACME account configured", "email", req.Email, "url", p.acmeURL)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "ACME account configured", "email": req.Email})
}

func (p *Plugin) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	email := p.acmeEmail
	if email == "" && p.configStore != nil {
		account, err := p.configStore.GetACMEAccount(r.Context())
		if err == nil {
			email = account.Email
		}
	}

	if email == "" {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "ACME account not configured"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"email": email})
}

// --- Role endpoints ---

func (p *Plugin) handleRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}

	if p.configStore == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "config storage not initialized"})
		return
	}

	names, err := p.configStore.ListRoles(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to list roles: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"roles": names})
}

func (p *Plugin) handleRole(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/config/roles/")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "role name is required"})
		return
	}

	switch r.Method {
	case http.MethodPut:
		p.handleSetRole(w, r, path)
	case http.MethodGet:
		p.handleGetRole(w, r, path)
	case http.MethodDelete:
		p.handleDeleteRole(w, r, path)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
	}
}

func (p *Plugin) handleSetRole(w http.ResponseWriter, r *http.Request, name string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "failed to read request body"})
		return
	}

	var req DNSRoleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON: " + err.Error()})
		return
	}

	if req.Provider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "provider is required"})
		return
	}
	if req.AllowedNames == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "allowed_names is required"})
		return
	}
	if len(req.Credentials) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "credentials are required"})
		return
	}

	// Validate the provider name is known (lazy validation — credentials checked at enrollment time)
	if err := p.registry.ValidateProvider(req.Provider); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid provider: " + err.Error()})
		return
	}

	role := &storage.DNSRole{
		Name:         name,
		Provider:     req.Provider,
		Credentials:  req.Credentials,
		AllowedNames: req.AllowedNames,
	}

	if p.configStore != nil {
		if err := p.configStore.SetRole(r.Context(), role); err != nil {
			p.logger.Error("failed to store role", "name", name, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to store role"})
			return
		}
	}

	p.logger.Info("DNS role configured", "name", name, "provider", role.Provider, "allowed", req.AllowedNames)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "role configured", "name": name, "provider": role.Provider})
}

func (p *Plugin) handleGetRole(w http.ResponseWriter, r *http.Request, name string) {
	if p.configStore == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "config storage not initialized"})
		return
	}

	role, err := p.configStore.GetRole(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "role not found"})
		return
	}

	writeJSON(w, http.StatusOK, role)
}

func (p *Plugin) handleDeleteRole(w http.ResponseWriter, r *http.Request, name string) {
	if p.configStore == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "config storage not initialized"})
		return
	}

	if err := p.configStore.DeleteRole(r.Context(), name); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to delete role: " + err.Error()})
		return
	}

	p.logger.Info("DNS role deleted", "name", name)
	writeJSON(w, http.StatusOK, map[string]interface{}{"message": "role deleted", "name": name})
}

// --- Enrollment endpoints ---

func (p *Plugin) handleEnroll(w http.ResponseWriter, r *http.Request) {
	csrPEM, _, _, acmeURL, err := p.parseEnrollRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}

	csrInfo, err := cryptoPkg.ParseCSRFromString(csrPEM)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid CSR: " + err.Error()})
		return
	}

	if len(csrInfo.Domains) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "CSR has no domain names"})
		return
	}

	p.logger.Info("enrollment requested", "domains", csrInfo.Domains)

	// Create enrollment
	enrollmentID := generateID()

	state := enroll.NewEnrollmentState(
		enrollmentID,
		csrPEM,
		csrInfo.Domains,
		acmeURL,
	)
	state.ACMEEmail = p.acmeEmail
	state.Credentials = map[string]interface{}{}

	if p.enrollStore != nil {
		if err := p.enrollStore.CreateEnrollment(r.Context(), state); err != nil {
			p.logger.Error("failed to store enrollment", "id", enrollmentID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to create enrollment"})
			return
		}
	}

	if p.issuer != nil {
		p.issuer.StartEnrollment(r.Context(), enrollmentID)
	}

	p.logger.Info("enrollment started", "id", enrollmentID, "domains", csrInfo.Domains)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":            enrollmentID,
		"state":         "pending",
		"domains":       csrInfo.Domains,
		"message":       "enrollment initiated, DNS-01 challenge in progress",
		"retrieve_url":  "/enroll/retrieve/" + enrollmentID,
	})
}

func (p *Plugin) parseEnrollRequest(r *http.Request) (csrPEM, acmeEmail, acmeKeyPEM, acmeURL string, err error) {
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			return "", "", "", "", fmt.Errorf("failed to read request body: %w", readErr)
		}
		var req struct {
			CSR        string `json:"csr"`
			ACMEEmail  string `json:"acme_email"`
			ACMEKeyPEM string `json:"acme_key_pem"`
			ACMEURL    string `json:"acme_url"`
		}
		if jsonErr := json.Unmarshal(body, &req); jsonErr == nil {
			return req.CSR, req.ACMEEmail, req.ACMEKeyPEM, req.ACMEURL, nil
		}
	}

	if parseErr := r.ParseMultipartForm(10 << 20); parseErr == nil {
		csrPEM = r.FormValue("csr")
		acmeEmail = r.FormValue("acme_email")
		acmeKeyPEM = r.FormValue("acme_key_pem")
		acmeURL = r.FormValue("acme_url")
		return
	}

	var body []byte
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		return "", "", "", "", fmt.Errorf("failed to read request body: %w", readErr)
	}
	var req struct {
		CSR        string `json:"csr"`
		ACMEEmail  string `json:"acme_email"`
		ACMEKeyPEM string `json:"acme_key_pem"`
		ACMEURL    string `json:"acme_url"`
	}
	if jsonErr := json.Unmarshal(body, &req); jsonErr == nil {
		return req.CSR, req.ACMEEmail, req.ACMEKeyPEM, req.ACMEURL, nil
	}
	return "", "", "", "", fmt.Errorf("invalid request body")
}

func (p *Plugin) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	id := ""

	// Try path parameter first (from /enroll/retrieve/{id})
	if strings.HasPrefix(r.URL.Path, "/enroll/retrieve/") {
		id = strings.TrimPrefix(r.URL.Path, "/enroll/retrieve/")
		if id == "" || id == "new" {
			id = ""
		}
	}

	// If no path, try body
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
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "enrollment ID is required"})
		return
	}

	p.doRetrieve(w, id)
}

func (p *Plugin) doRetrieve(w http.ResponseWriter, id string) {
	if p.enrollStore == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "enrollment storage not initialized"})
		return
	}

	state, err := p.enrollStore.GetEnrollment(context.Background(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "enrollment not found: " + err.Error()})
		return
	}

	switch state.State {
	case "pending", "in_progress":
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id": state.ID, "state": state.State, "domains": state.Domains,
			"message": "enrollment in progress",
		})
	case "completed":
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id": state.ID, "state": "completed", "domains": state.Domains,
			"certificate": state.Certificate, "issued_at": state.UpdatedAt.Format(time.RFC3339),
			"not_after": state.NotAfter.Format(time.RFC3339), "message": "certificate issued successfully",
		})
	case "error":
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id": state.ID, "state": "error", "domains": state.Domains, "error": state.Error,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id": state.ID, "state": state.State, "domains": state.Domains,
		})
	}
}

// --- Revoke endpoint ---

func (p *Plugin) handleRevoke(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "failed to read request body"})
		return
	}

	var req struct {
		Certificate string `json:"certificate"`
		ID          string `json:"id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid JSON: " + err.Error()})
		return
	}

	// If an enrollment ID is provided, cancel the in-progress enrollment
	if req.ID != "" {
		if p.enrollStore == nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "enrollment storage not initialized"})
			return
		}
		state, err := p.enrollStore.GetEnrollment(r.Context(), req.ID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"error": "enrollment not found: " + err.Error()})
			return
		}
		state.State = "cancelled"
		p.enrollStore.UpdateEnrollment(r.Context(), state)
		p.logger.Info("enrollment cancelled", "id", req.ID)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":      req.ID,
			"message": "enrollment cancelled",
			"domains": state.Domains,
		})
		return
	}

	// If no certificate, require an ID
	if req.Certificate == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "certificate or enrollment id is required"})
		return
	}

	certParsed, err := cryptoPkg.ParseCertificate([]byte(req.Certificate))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid certificate: " + err.Error()})
		return
	}

	key, err := parseKey([]byte(p.acmeKeyPEM))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to parse ACME key: " + err.Error()})
		return
	}

	acmeURL := p.acmeURL
	if acmeURL == "" {
		acmeURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	user := &acmeUser{
		email:      p.acmeEmail,
		privateKey: key,
		reg:        nil,
	}

	config := lego.NewConfig(user)
	config.CADirURL = acmeURL
	config.Certificate.KeyType = "RSA2048"
	config.UserAgent = "openbao-dnsacme-plugin"

	client, err := lego.NewClient(config)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to create ACME client: " + err.Error()})
		return
	}

	// Parse the certificate to get DER bytes
	parsedCert, err := x509.ParseCertificate([]byte(req.Certificate))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "failed to parse certificate: " + err.Error()})
		return
	}

	if err := client.Certificate.Revoke(parsedCert.Raw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "failed to revoke certificate: " + err.Error()})
		return
	}

	p.logger.Info("certificate revoked", "serial", certParsed.SerialNumber.String())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "certificate revoked", "serial": certParsed.SerialNumber.String(),
	})
}

// --- Helpers ---

func generateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err == nil {
		return hex.EncodeToString(bytes)
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

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

// DNSRoleRequest is the request body for setting a DNS role.
type DNSRoleRequest struct {
	Provider     string                 `json:"provider"`
	Credentials  map[string]interface{} `json:"credentials"`
	AllowedNames string                 `json:"allowed_names"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// --- Main entry point ---

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:       "dnsacme",
		Level:      hclog.Trace,
		Output:     hclog.DefaultOutput,
		JSONFormat: true,
	})

	// Standalone HTTP mode: check for -listen/-standalone flag
	for _, arg := range os.Args[1:] {
		if arg == "-listen" || arg == "-standalone" {
			impl := buildPlugin(logger)
			mux := http.NewServeMux()
			impl.RegisterPaths(mux)

			addr := ":8202"
			logger.Info("DNS-01 ACME plugin starting in standalone mode", "addr", addr)
			fmt.Println("DEBUG: Starting HTTP server on", addr)
			if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
				logger.Error("plugin server failed", "error", err)
				fmt.Println("DEBUG: Server stopped with error:", err)
			} else {
				fmt.Println("DEBUG: Server stopped cleanly")
			}
			return
		}
	}

	// Native OpenBao plugin mode: serve gRPC over stdin/stdout
	impl := buildPlugin(logger)
	logger.Info("DNS-01 ACME plugin starting in native plugin mode")
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			MagicCookieKey:   "VAULT_BACKEND_PLUGIN",
			MagicCookieValue: "6669da05-b1c8-4f49-97d9-c8e5bed98e20",
		},
		VersionedPlugins: map[int]plugin.PluginSet{
			3: {
				"backend": &pb.GRPCBackendPlugin{
					Factory: func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
						if impl.configStore == nil {
							impl.Init(ctx, &openbaoStorageView{storage: config.StorageView})
						}
						return &dnsacmeBackend{Plugin: impl, logger: logger}, nil
					},
					Logger: logger,
				},
			},
			4: {
				"backend": &pb.GRPCBackendPlugin{
					Factory: func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
						if impl.configStore == nil {
							impl.Init(ctx, &openbaoStorageView{storage: config.StorageView})
						}
						return &dnsacmeBackend{Plugin: impl, logger: logger}, nil
					},
					Logger: logger,
				},
			},
			5: {
				"backend": &pb.GRPCBackendPlugin{
					Factory:             func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
						if impl.configStore == nil {
							impl.Init(ctx, &openbaoStorageView{storage: config.StorageView})
						}
						return &dnsacmeBackend{Plugin: impl, logger: logger}, nil
					},
					Logger: logger,
				},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

func buildPlugin(logger hclog.Logger) *Plugin {
	impl := NewPlugin(logger)

	// Register the lego provider factory under all known lego provider names.
	// This allows any lego-supported DNS provider (cloudflare, route53, etc.)
	// to be used by referencing the provider name in the role config.
	factory := &dns.LegoProviderFactory{}
	for _, name := range dns.ListSupportedProviders() {
		impl.registry.Register(name, factory)
	}

	// Store logger reference for backend use
	impl.logger = logger

	return impl
}
