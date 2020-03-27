package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) roleVenafiSync(ctx context.Context, req *logical.Request) (err error) {

	//Get role list with role sync param
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return
	}

	if len(roles) == 0 {
		return
	}
	//name
	//sync zone name\id
	//sync endpoint


	for _, roleName := range roles {
		//	Read previous role parameters
		entry, err := b.getPKIRoleEntry(ctx, req, roleName)
		//Get Venafi policy in entry format
		venafiPolicy, err := b.getVenafiPolicyParams(ctx, req, defaultVenafiPolicyName)
		if err != nil {
			return err
		}
		//  Rewrite entry
		entry.OU = venafiPolicy.OU
		entry.Organization = venafiPolicy.Organization
		entry.Country = venafiPolicy.Country
		entry.Locality = venafiPolicy.Locality
		entry.Province = venafiPolicy.Province
		entry.StreetAddress = venafiPolicy.StreetAddress
		entry.PostalCode = venafiPolicy.PostalCode

		// Put new entry
		jsonEntry, err := logical.StorageEntryJSON("role/"+roleName, entry)
		if err != nil {
			return err
		}
		if err := req.Storage.Put(ctx, jsonEntry); err != nil {
			return err
		}
	}

	return err
}

func (b *backend) getVenafiPolicyParams(ctx context.Context, req *logical.Request, policyConfig string) (entry roleEntry, err error) {
	//Get role params from TPP\Cloud
	cl, err := b.ClientVenafi(ctx, req.Storage, policyConfig, "policy")
	if err != nil {
		return entry, fmt.Errorf("could not create venafi client: %s", err)
	}

	zone, err := cl.ReadZoneConfiguration()
	if err != nil {
		return
	}
	entry = roleEntry{
		OU:            zone.OrganizationalUnit,
		Organization:  []string{zone.Organization},
		Country:       []string{zone.Country},
		Locality:      []string{zone.Locality},
		Province:      []string{zone.Province},
	}
	return
}

func (b *backend) getPKIRoleEntry(ctx context.Context, req *logical.Request, roleName string) (entry roleEntry, err error) {
	//Update role since it's settings may be changed
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return entry, fmt.Errorf("Error getting role %v: %s\n", role, err)
	}
	entry = roleEntry{
		AllowLocalhost:   true,
		AllowedDomains:   []string{"venafi.com"},
		AllowBareDomains: true,
		AllowSubdomains:  true,
		AllowGlobDomains: true,
		AllowAnyName:     true,
		EnforceHostnames: true,

		OU:            []string{"DevOps-old"},
		Organization:  []string{"Venafi-old"},
		Country:       []string{"US-old"},
		Locality:      []string{"Salt Lake-old"},
		Province:      []string{"Venafi-old"},
		StreetAddress: []string{"Venafi-old"},
		PostalCode:    []string{"122333344-old"},
	}
	return entry, nil
}