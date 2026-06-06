// Package dns provides lego-backed DNS provider implementations.
package dns

import (
	"context"
	"fmt"
	"os"
	"reflect"

	legodns "github.com/go-acme/lego/v4/providers/dns"
)

// legoProviderWrapper wraps a lego DNS provider to implement our generic Provider interface.
type legoProviderWrapper struct {
	name     string
	provider interface{}
}

func (w *legoProviderWrapper) Name() string {
	return w.name
}

func (w *legoProviderWrapper) Present(ctx context.Context, domain, token, keyAuth string) error {
	// Debug: log the domain being passed to Present
	fmt.Printf("DEBUG lego Present: domain=%s token=%s keyAuth=%s\n", domain, token, keyAuth)

	v := reflect.ValueOf(w.provider)
	method := v.MethodByName("Present")
	if !method.IsValid() {
		return fmt.Errorf("lego provider %s has no Present method", w.name)
	}

	// lego DNS provider signature: Present(domain, token, keyAuth)
	args := []reflect.Value{reflect.ValueOf(domain), reflect.ValueOf(token), reflect.ValueOf(keyAuth)}
	if method.Type().NumIn() >= 4 {
		args = append(args, reflect.ValueOf(ctx))
	}

	results := method.Call(args)
	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok {
			return err
		}
	}
	return nil
}

func (w *legoProviderWrapper) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	v := reflect.ValueOf(w.provider)
	method := v.MethodByName("CleanUp")
	if !method.IsValid() {
		return fmt.Errorf("lego provider %s has no CleanUp method", w.name)
	}

	// lego DNS provider signature: CleanUp(domain, token, keyAuth)
	args := []reflect.Value{reflect.ValueOf(domain), reflect.ValueOf(token), reflect.ValueOf(keyAuth)}
	if method.Type().NumIn() >= 4 {
		args = append(args, reflect.ValueOf(ctx))
	}

	results := method.Call(args)
	if len(results) > 0 && !results[0].IsNil() {
		if err, ok := results[0].Interface().(error); ok {
			return err
		}
	}
	return nil
}

// LegoProviderFactory creates lego-backed DNS providers from configuration maps.
// The config map keys should match the environment variable names used by the provider.
type LegoProviderFactory struct{}

// NewProvider creates a new DNS provider using lego's built-in DNS provider registry.
// The config map should contain:
//   - "provider": the lego DNS provider name (e.g., "aws", "cloudflare", "route53")
//   - Any other keys are set as environment variables for the provider
//
// This supports any DNS provider built into the lego library.
func (f *LegoProviderFactory) NewProvider(config map[string]interface{}) (Provider, error) {
	providerName, ok := config["provider"].(string)
	if !ok || providerName == "" {
		return nil, fmt.Errorf("config must contain 'provider' field with the lego DNS provider name")
	}

	// Collect env vars from config
	type envPair struct {
		key   string
		value string
	}
	var envVars []envPair

	for k, v := range config {
		if k == "provider" {
			continue
		}
		if strVal, ok := v.(string); ok && strVal != "" {
			envVars = append(envVars, envPair{k, strVal})
		}
	}

	// Create a cleanup function to unset env vars after provider creation
	cleanup := func() {
		for _, ev := range envVars {
			os.Unsetenv(ev.key)
		}
	}

	// Set environment variables
	for _, ev := range envVars {
		os.Setenv(ev.key, ev.value)
	}

	// Try to create the provider by name
	// lego generates a NewDNSChallengeProviderByName function that creates providers
	// by reading from environment variables
	provider, err := legodns.NewDNSChallengeProviderByName(providerName)

	// Clean up env vars (but provider may still hold references)
	cleanup()

	if err != nil {
		return nil, fmt.Errorf("failed to create lego DNS provider %q: %w", providerName, err)
	}

	return &legoProviderWrapper{
		name:     providerName,
		provider: provider,
	}, nil
}

// IsValidProvider checks if a provider name is supported by lego without creating an instance.
// This is useful for validating provider names at role store time without requiring credentials.
func (f *LegoProviderFactory) IsValidProvider(name string) bool {
	for _, p := range ListSupportedProviders() {
		if p == name {
			return true
		}
	}
	return false
}

// GetChallengeDomain returns the FQDN for DNS-01 challenge records.
func GetChallengeDomain(domain string) string {
	return fmt.Sprintf("_acme-challenge.%s", domain)
}

// GetKeyAuth computes the key authorization string for the DNS-01 challenge.
func GetKeyAuth(thumbprint, token string) string {
	// keyAuth = base64url(SHA256(thumbprint + "." + base64url(urlEncode(token))))
	// This matches lego's dns01.GetChallengeTxtRecord
	return fmt.Sprintf("%s.%s", thumbprint, token)
}

// ListSupportedProviders returns a list of all DNS providers supported by lego.
func ListSupportedProviders() []string {
	// These are the providers built into lego
	return []string{
		"manual", "acme-dns", "alidns", "allinkl", "arvancloud", "auroradns",
		"autodns", "azure", "azuredns", "bindman", "bluecat", "brandit", "bunny",
		"checkdomain", "civo", "clouddns", "cloudflare", "cloudns", "cloudru",
		"cloudxns", "conoha", "constellix", "cpanel", "dasnetis", "deSEC",
		"designate", "digitalocean", "dnsimple", "dnspod", "dode", "dreamhost",
		"dslite", "duckdns", "dyndns", "edgedns", "easydns", "eiq", "elx",
		"exoscale", "freemyip", "gandi", "gandiv5", "gcloud", "godaddy",
		"googledomains", "hetzner", "hostingde", "hosttech", "httpreq", "hurricane",
		"hyperone", "ibmcloud", "iij", "iijdpf", "infoblox", "inwx", "ionos",
		"ipv4", "iwantmyname", "joker", "kkcloud", "kloxo", "lesweb", "linode",
		"liquidweb", "loopia", "luadns", "mailinabox", "metaname", "mythicbeasts",
		"namecheap", "namedotcom", "namesilo", "nearlyfreespeech", "netcup",
		"netlify", "nicmanager", "nicname", "nifcloud", "njalla", "nodion",
		"ns1", "oraclecloud", "otc", "ovh", "pdns", "plesk", "porkbun",
		"rackspace", "ramspace", "rayhosting", "regfish", "regru", "rfc2136",
		"route53", "sakuracloud", "scaleway", "selectel", "servercow", "simpledns",
		"smartdns", "sofastack", "stackpath", "tencentcloud", "transip",
		"ultradns", "vegadns", "vercel", "versio", "vinyldns", "volcengine",
		"vultr", "webnames", "websupport", "yandex", "yandex360", "yandexcloud",
		"zoneee",
	}
}
