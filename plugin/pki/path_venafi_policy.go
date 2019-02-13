//TODO: write get and save venafi policy here.
package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/helper/errutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
)

// This returns the list of queued for import to TPP certificates
func pathVenafiPolicy(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "venafi-policy",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathUpdateVenafiPolicy,
			logical.ReadOperation:   b.pathReadVenafiPolicy,
			logical.ListOperation:   b.pathListVenafiPolicy,
			logical.DeleteOperation: b.pathDeleteVenafiPolicy,
		},

		HelpSynopsis:    pathVenafiPolicySyn,
		HelpDescription: pathVenafiPolicyDesc,
	}
	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func (b *backend) pathUpdateVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	//TODO: Get policy from TPP of Cloud
	//TODO: Write it into req.Storage using Put (err = req.Storage.Put(ctx, entry))
	//TODO: Return policy so user can read it
	ctx = context.Background()

	return nil, nil
}

func (b *backend) pathReadVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	//TODO: read policy content
	return nil, nil
}

func (b *backend) pathListVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	//TODO: list policies if we will decide to implement multiple policies per plugin
	return nil, nil
}

func (b *backend) pathDeleteVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	//TODO: delete policy
	return nil, nil
}

func checkAgainstVenafiPolicy(b *backend, data *dataBundle) error {
	ctx := context.Background()
	//TODO: Check that policy exists
	//TODO: Get and parse Venafi policy
	policy, err := data.req.Storage.Get(ctx, "venafi-policy")
	if err != nil {
		return err
	}
	//TODO: If nothing exists in the policy deny all.
	log.Printf("Checking creation bundle %s against policy %s", "data", policy)
	//TODO: Check data *dataBundle against Venafi polycu.
	//TODO: in case of exception return errutil.UserError{}
	if "data-bundle" != "policy-checks" {
		return errutil.UserError{Err: fmt.Sprintf(
			"Not implemented yet")}
	}
	return nil
}

const pathVenafiPolicySyn = `help here`
const pathVenafiPolicyDesc = `description here`
