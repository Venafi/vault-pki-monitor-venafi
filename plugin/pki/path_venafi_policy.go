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
		Pattern: "venafi-policy/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the Venafi policy",
			},

			"tpp_url": {
				Type:        framework.TypeString,
				Description: `URL of Venafi Platfrom. Example: https://tpp.venafi.example/vedsdk`,
				Required:    true,
			},
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platfrom or Cloud policy. 
Example for Platform: testpolicy\\vault
Example for Venafi Cloud: Default`,
				Default: `Default`,
			},
			"tpp_user": {
				Type:        framework.TypeString,
				Description: `web API user for Venafi Platfrom Example: admin`,
				Required:    true,
			},
			"tpp_password": {
				Type:        framework.TypeString,
				Description: `Password for web API user Example: password`,
				Required:    true,
			},
			"tpp_import": {
				Type:        framework.TypeBool,
				Description: `Import certificate to Venafi Platform if true. False by default.`,
				Required:    true,
			},
			"trust_bundle_file": {
				Type: framework.TypeString,
				Description: `Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.
Example:
  trust_bundle_file = "/full/path/to/chain.pem""`,
			},
			"apikey": {
				Type:        framework.TypeString,
				Description: `API key for Venafi Cloud. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
			},
			"cloud_url": {
				Type:        framework.TypeString,
				Description: `URL for Venafi Cloud. Set it only if you want to use non production Cloud`,
			},
		},
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

func (b *backend) pathUpdateVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)

	//TODO: Get policy from TPP of Cloud
	//cl, err := b.ClientVenafi(ctx, req.Storage, data, req, roleName)
	//TODO: Write it into req.Storage using Put (err = req.Storage.Put(ctx, entry))
	entry := &policyEntry{
		TPPURL:          data.Get("tpp_url").(string),
		CloudURL:        data.Get("cloud_url").(string),
		Zone:            data.Get("zone").(string),
		TPPPassword:     data.Get("tpp_password").(string),
		Apikey:          data.Get("apikey").(string),
		TPPUser:         data.Get("tpp_user").(string),
		TrustBundleFile: data.Get("trust_bundle_file").(string),

	}
	if entry.Apikey == "" && (entry.TPPURL == "" || entry.TPPUser == "" || entry.TPPPassword == "") {
		return logical.ErrorResponse("Invalid mode. apikey or tpp credentials required"), nil
	}
	jsonEntry, err := logical.StorageEntryJSON("role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	//TODO: Return policy so user can read it
	//policy :=

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

func (b *backend) getPolicy(ctx context.Context, s logical.Storage, n string) (*policyEntry, error) {
	entry, err := s.Get(ctx, "venafi-policy/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result policyEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

type policyEntry struct {
	TPPURL          string `json:"tpp_url"`
	Zone            string `json:"zone"`
	TPPPassword     string `json:"tpp_password"`
	TPPUser         string `json:"tpp_user"`
	TPPImport       bool   `json:"tpp_import"`
	TrustBundleFile string `json:"trust_bundle_file"`
	Apikey          string `json:"apikey"`
	CloudURL        string `json:"cloud_url"`
}

const pathVenafiPolicySyn = `help here`
const pathVenafiPolicyDesc = `description here`
