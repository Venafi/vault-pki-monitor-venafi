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
		pkiRoleEntry, err := b.getPKIRoleEntry(ctx, req, roleName)
		//Get Venafi policy in entry format
		venafiPolicyEntry, err := b.getVenafiPolicyParams(ctx, req, defaultVenafiPolicyName)
		if err != nil {
			return err
		}
		//  Replace PKI entry with Venafi policy values
		pkiRoleEntry.OU = venafiPolicyEntry.OU
		pkiRoleEntry.Organization = venafiPolicyEntry.Organization
		pkiRoleEntry.Country = venafiPolicyEntry.Country
		pkiRoleEntry.Locality = venafiPolicyEntry.Locality
		pkiRoleEntry.Province = venafiPolicyEntry.Province
		pkiRoleEntry.StreetAddress = venafiPolicyEntry.StreetAddress
		pkiRoleEntry.PostalCode = venafiPolicyEntry.PostalCode

		// Put new entry
		jsonEntry, err := logical.StorageEntryJSON("role/"+roleName, pkiRoleEntry)
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

func (b *backend) getPKIRoleEntry(ctx context.Context, req *logical.Request, roleName string) (entry *roleEntry, err error) {
	//Update role since it's settings may be changed
	entry, err = b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return entry, fmt.Errorf("Error getting role %v: %s\n", roleName, err)
	}
	return entry, nil
}