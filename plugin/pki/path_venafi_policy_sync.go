package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
)

const venafiSyncPolicyListPath = "venafi-sync-policies"

func pathVenafiPolicySync(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiSyncPolicyListPath,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathReadVenafiPolicySync,
		},
	}
	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func (b *backend) pathReadVenafiPolicySync(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	//Get role list with role sync param
	log.Println("starting to read sync  roles")
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("No roles found in storage")
	}

	var entries []string

	for _, roleName := range roles {
		log.Println("looking role ", roleName)
		//	Read previous role parameters
		pkiRoleEntry, err := b.getPKIRoleEntry(ctx, req.Storage, roleName)
		if err != nil {
			log.Printf("%s", err)
			continue
		}

		if pkiRoleEntry == nil {
			continue
		}

		//Get Venafi policy in entry format
		if pkiRoleEntry.VenafiSyncPolicy == "" {
			continue
		}

		var entry []string
		entry = append(entry, fmt.Sprintf("role: %s sync policy: %s", roleName, pkiRoleEntry.VenafiSyncPolicy))
		entries = append(entries, entry...)

	}
	return logical.ListResponse(entries), nil
}
