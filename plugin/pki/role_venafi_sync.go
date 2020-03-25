package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) roleVenafiSync(ctx context.Context, req *logical.Request) (response *logical.Response, err error) {

	//Get role list with role sync param
	//name
	//sync zone name\id
	//sync endpoint

	//For each role do:
	roleName := "venafi-sync-role"
	//Get role params from TPP\Cloud
	cl, err := b.ClientVenafi(ctx, req.Storage, roleName, "role")
	if err != nil {
		return response, fmt.Errorf("could not create venafi client: %s", err)
	}

	zone, err := cl.ReadZoneConfiguration()
	if err != nil {
		return
	}
	//Set role parameters
	entryRewrite := &roleEntry{
		OU:            zone.SubjectOURegexes,
		Organization:  []string{"Venafi"},
		Country:       []string{zone.Country},
		Locality:      []string{"Salt Lake"},
		Province:      []string{"Venafi"},
		StreetAddress: []string{"Venafi"},
		PostalCode:    []string{"122333344"},
	}
	//	Read previous role parameters
	entryOriginal := &roleEntry{
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
	//  Make new entry
	//implement merge
	mergedEntry := entryOriginal
	mergedEntry.OU = entryRewrite.OU
	mergedEntry.Organization = entryRewrite.Organization
	mergedEntry.Country = entryRewrite.Country
	mergedEntry.Locality = entryRewrite.Locality
	mergedEntry.Province = entryRewrite.Province
	mergedEntry.StreetAddress = entryRewrite.StreetAddress
	mergedEntry.PostalCode = entryRewrite.PostalCode



	// Put new entry
	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+roleName, entryRewrite)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}
	return
}
