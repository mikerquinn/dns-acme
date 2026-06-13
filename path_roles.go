package main

import (
	"context"
	"fmt"

	"github.com/mikerquinn/dns-acme/dns"
	"github.com/mikerquinn/dns-acme/storage"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// toResponseData returns response data for a role.
func toResponseData(r *storage.DNSRole) map[string]interface{} {
	return map[string]interface{}{
		"name":        r.Name,
		"provider":    r.Provider,
		"zone":        r.Zone,
		"credentials": r.Credentials,
	}
}

// pathConfigRoles returns the role listing and CRUD paths.
func pathConfigRoles(b *dnsacmeBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"provider": {
					Type:        framework.TypeString,
					Description: "DNS provider name (e.g. cloudflare, route53, gandi)",
					Required:    true,
				},
				"zone": {
					Type:        framework.TypeString,
					Description: "DNS zone the API key controls (e.g. example.com). Required. The API key must have permissions for this zone and all subdomains.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
					Summary:  "Get a DNS provider role",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
					Summary:  "Create a DNS provider role",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
					Summary:  "Update a DNS provider role",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
					Summary:  "Delete a DNS provider role",
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "config/roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
					Summary:  "List DNS provider roles",
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// pathRolesList returns a list of role names.
func (b *dnsacmeBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, configKeyRoles)
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead reads a role and returns response data.
func (b *dnsacmeBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return &logical.Response{Data: map[string]interface{}{"error": "name is required"}}, nil
	}

	role, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}

	if role == nil {
		return &logical.Response{Data: map[string]interface{}{"error": "role not found"}}, nil
	}

	return &logical.Response{
		Data: toResponseData(role),
	}, nil
}

// pathRolesWrite creates or updates a role.
func (b *dnsacmeBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return &logical.Response{Data: map[string]interface{}{"error": "name is required"}}, nil
	}
	nameStr := name.(string)

	provider, ok := d.GetOk("provider")
	if !ok {
		return &logical.Response{Data: map[string]interface{}{"error": "provider is required"}}, nil
	}
	providerStr := provider.(string)

	zone, ok := d.GetOk("zone")
	if !ok {
		return &logical.Response{Data: map[string]interface{}{"error": "zone is required"}}, nil
	}
	zoneStr := zone.(string)

	if err := dnsacmeBackendValidateProvider(b.registry, providerStr); err != nil {
		return &logical.Response{Data: map[string]interface{}{"error": "invalid provider: " + err.Error()}}, nil
	}

	role, err := b.getRole(ctx, req.Storage, nameStr)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if role == nil {
		role = &storage.DNSRole{}
	}

	if createOperation {
		role.Name = nameStr
	}

	role.Provider = providerStr
	role.Zone = zoneStr

	// Collect credential fields from the raw data (skip known framework fields)
	credentials := make(map[string]interface{})
	for k, v := range d.Raw {
		switch k {
		case "name", "provider", "zone", "_",
			"_wrap_ttl", "wrap_info", "wrap_ttl", "token_lookup", "token_policies", "token_no_default_policy",
			"lease_options", "metadata", "data":
			continue
		}
		credentials[k] = v
	}
	role.Credentials = credentials

	if err := setRole(ctx, req.Storage, nameStr, role); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"message":  "role configured",
			"name":     nameStr,
			"provider": providerStr,
		},
	}, nil
}

// pathRolesDelete deletes a role.
func (b *dnsacmeBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return &logical.Response{Data: map[string]interface{}{"error": "name is required"}}, nil
	}

	err := req.Storage.Delete(ctx, configKeyRoles+name.(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}

	return nil, nil
}

// getRole retrieves a role from storage.
func (b *dnsacmeBackend) getRole(ctx context.Context, s logical.Storage, name string) (*storage.DNSRole, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, configKeyRoles+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role storage.DNSRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// setRole adds or updates a role in storage.
func setRole(ctx context.Context, s logical.Storage, name string, role *storage.DNSRole) error {
	entry, err := logical.StorageEntryJSON(configKeyRoles+name, role)
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

// dnsacmeBackendValidateProvider checks if a provider name is registered.
func dnsacmeBackendValidateProvider(registry *dns.ProviderRegistry, name string) error {
	return registry.ValidateProvider(name)
}

const (
	pathRoleHelpSynopsis = `Manages the DNS provider role for certificate issuance.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate DNS credentials
for certificate issuance. Each role maps a DNS provider (e.g., cloudflare,
route53) to a DNS zone and a set of credentials.

During enrollment, the first role whose zone matches the requested domain
(equals the zone or is a subdomain of it) is used.
`

	pathRoleListHelpSynopsis    = `List the existing DNS provider roles.`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`
)
