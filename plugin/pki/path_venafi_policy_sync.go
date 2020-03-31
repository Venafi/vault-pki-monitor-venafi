package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"time"
)

func (b *backend) syncWithVenafiPolicyRegister(storage logical.Storage, conf *logical.BackendConfig) {
	b.taskStorage.register("policy-sync-controller", func() {
		b.syncWithVenafiPolicyController(storage)
	}, 1, time.Second)
}

func (b *backend) syncWithVenafiPolicyController(storage logical.Storage) {
	err := b.syncWithVenafiPolicy(storage)
	if err != nil {
		log.Printf("%s", err)
	}
}

func (b *backend) syncWithVenafiPolicy(storage logical.Storage) (err error) {

	ctx := context.Background()
	//Get role list with role sync param
	roles, err := storage.List(ctx, "role/")
	if err != nil {
		return
	}

	if len(roles) == 0 {
		return
	}

	for _, roleName := range roles {
		//	Read previous role parameters
		pkiRoleEntry, err := b.getPKIRoleEntry(ctx, storage, roleName)
		if err != nil {
			log.Printf("%s", err)
			continue
		}

		if pkiRoleEntry == nil {
			log.Printf("PKI role %s is empty or does not exist", roleName)
			continue
		}

		if !pkiRoleEntry.VenafiSync {
			continue
		}

		//Get Venafi policy in entry format
		venafiPolicyEntry, err := b.getVenafiPolicyParams(ctx, storage, pkiRoleEntry.VenafiSyncPolicy,
			pkiRoleEntry.VenafiSyncZone)
		if err != nil {
			log.Printf("%s", err)
			continue
		}

		//  Replace PKI entry with Venafi policy values
		pkiRoleEntry.OU = venafiPolicyEntry.OU
		pkiRoleEntry.Organization = venafiPolicyEntry.Organization
		pkiRoleEntry.Country = venafiPolicyEntry.Country
		pkiRoleEntry.Locality = venafiPolicyEntry.Locality
		pkiRoleEntry.Province = venafiPolicyEntry.Province
		pkiRoleEntry.StreetAddress = venafiPolicyEntry.StreetAddress
		pkiRoleEntry.PostalCode = venafiPolicyEntry.PostalCode

		//does not have to configure the role to limit domains
		// because the Venafi policy already constrains that area
		pkiRoleEntry.AllowAnyName = true
		pkiRoleEntry.AllowedDomains = []string{}
		pkiRoleEntry.AllowSubdomains = true

		// Put new entry
		jsonEntry, err := logical.StorageEntryJSON("role/"+roleName, pkiRoleEntry)
		if err != nil {
			return err
		}
		if err := storage.Put(ctx, jsonEntry); err != nil {
			return err
		}
	}

	return err
}

func (b *backend) getVenafiPolicyParams(ctx context.Context, storage logical.Storage, policyConfig string, syncZone string) (entry roleEntry, err error) {
	//Get role params from TPP\Cloud
	cl, err := b.ClientVenafi(ctx, storage, policyConfig, "policy")
	if err != nil {
		return entry, fmt.Errorf("could not create venafi client: %s", err)
	}

	cl.SetZone(syncZone)
	zone, err := cl.ReadZoneConfiguration()
	if err != nil {
		return
	}
	entry = roleEntry{
		OU:           zone.OrganizationalUnit,
		Organization: []string{zone.Organization},
		Country:      []string{zone.Country},
		Locality:     []string{zone.Locality},
		Province:     []string{zone.Province},
	}
	return
}

func (b *backend) getPKIRoleEntry(ctx context.Context, storage logical.Storage, roleName string) (entry *roleEntry, err error) {
	//Update role since it's settings may be changed
	entry, err = b.getRole(ctx, storage, roleName)
	if err != nil {
		return entry, fmt.Errorf("Error getting role %v: %s\n", roleName, err)
	}
	return entry, nil
}
