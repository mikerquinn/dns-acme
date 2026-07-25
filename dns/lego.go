// Package dns provides lego-backed DNS provider implementations.
package dns

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"

	legodns "github.com/go-acme/lego/v4/providers/dns"
)

// envMu serializes LegoProviderFactory.NewProvider calls so that the
// os.Setenv → provider-creation → os.Unsetenv window cannot interleave.
// Without this, concurrent enrollments can read each other's credentials.
var envMu sync.Mutex

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

// legoProviderWrapper wraps a lego DNS provider to implement our generic Provider interface.
type legoProviderWrapper struct {
	name     string
	provider interface{}
}

func (w *legoProviderWrapper) Name() string {
	return w.name
}

func (w *legoProviderWrapper) Present(ctx context.Context, domain, token, keyAuth string) error {
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

// LegoProviderFactory creates lego-backed DNS providers from role configuration maps.
type LegoProviderFactory struct{}

// NewProvider creates a new DNS provider using lego's built-in DNS provider registry.
// The config map should contain:
//
//	"provider": the lego DNS provider name (e.g., "cloudflare", "route53", "digitalocean")
//	"zone": (optional) DNS zone identifier (e.g. Cloudflare zone ID, Route53 hosted zone).
//          Set as the "ZONE" env var, which providers that need explicit zone info will use.
//
// All other string-valued keys are converted to uppercase environment variables
// as-is (e.g. "CLOUDFLARE_DNS_API_TOKEN" -> "CLOUDFLARE_DNS_API_TOKEN").
// No auto-prefixing is applied.
//
// This supports any DNS provider built into the lego library.
func (f *LegoProviderFactory) NewProvider(config map[string]interface{}) (Provider, error) {
	providerName, ok := config["provider"].(string)
	if !ok || providerName == "" {
		return nil, fmt.Errorf("config must contain 'provider' field with the lego DNS provider name")
	}

	// Collect env vars from config, tracking which keys we set so we can skip duplicates.
	// Config keys are converted to uppercase and used directly as env var names.
	// No auto-prefixing — admins specify the exact env var names lego expects
	// (e.g. "CLOUDFLARE_DNS_API_TOKEN", "AWS_ACCESS_KEY_ID").
	type envPair struct {
		key   string
		value string
	}
	var envVars []envPair
	setKeys := make(map[string]bool) // Track which env var names have been set

	// Set ZONE env var from the role's zone attribute if provided.
	// For Cloudflare, the provider looks up zones by name using the ZONE env var.
	// For providers like Route53, the zone is the hosted zone ID.
	if zone, ok := config["zone"].(string); ok && zone != "" {
		envVars = append(envVars, envPair{"ZONE", zone})
		envVars = append(envVars, envPair{strings.ToUpper(providerName) + "_ZONE", zone})
		setKeys["ZONE"] = true
		setKeys[strings.ToUpper(providerName)+"_ZONE"] = true
		// For Cloudflare, also set ZONE_ID if the zone looks like a domain name
		// (not a UUID-style ID), so the provider can resolve it.
		if strings.ToUpper(providerName) == "CLOUDFLARE" && !strings.Contains(zone, "-") && len(zone) > 4 {
			envVars = append(envVars, envPair{strings.ToUpper(providerName) + "_ZONE_ID", zone})
			setKeys[strings.ToUpper(providerName)+"_ZONE_ID"] = true
		}
	}

	for k, v := range config {
		if k == "provider" || k == "zone" {
			continue
		}
		if strVal, ok := v.(string); ok && strVal != "" {
			upperK := strings.ToUpper(k)
			if setKeys[upperK] {
				// Skip duplicate — the explicit ZONE handling above already set it.
				continue
			}
			envVars = append(envVars, envPair{upperK, strVal})
			setKeys[upperK] = true
		}
	}

	// Serialize the entire setenv→create→unsetenv window so that
	// concurrent NewProvider calls cannot interleave their environment variables.
	envMu.Lock()
	defer envMu.Unlock()

	// Set environment variables
	for _, ev := range envVars {
		os.Setenv(ev.key, ev.value)
	}

	// Create a cleanup function to unset env vars after provider creation
	cleanup := func() {
		for _, ev := range envVars {
			os.Unsetenv(ev.key)
		}
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
