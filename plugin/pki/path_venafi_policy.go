//TODO: write get and save venafi policy here.
package pki

import (
	"context"
	"github.com/Venafi/vcert/pkg/endpoint"
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
				Description: "Name of the Venafi policy config",
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
	return ret
}

func pathVenafiPolicyRead(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "venafi-policy/" + framework.GenericNameRegex("config") + "/policy",
		Fields: map[string]*framework.FieldSchema{
			"config": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the Venafi policy config",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathReadVenafiPolicyRead,
		},

		HelpSynopsis:    pathVenafiPolicySyn,
		HelpDescription: pathVenafiPolicyDesc,
	}
	return ret
}
func (b *backend) pathReadVenafiPolicyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := data.Get("config").(string)
	log.Printf("Trying to read policy for config %s", config)

	if len(config) == 0 {
		return logical.ErrorResponse("Non config specified or wrong config path name"), nil
	}

	entry, err := req.Storage.Get(ctx, "venafi-policy/"+config+"/policy")
	if err != nil {
		return nil, err
	}

	var policy venafiPolicyEntry

	if err := entry.DecodeJSON(&policy); err != nil {
		log.Printf("error reading Venafi policy configuration: %s", err)
		return nil, err
	}

	//Send policy to the user output
	respData := map[string]interface{}{
		"subject_cn_regexes": policy.SubjectCNRegexes,
		"subject_or_egexes":  policy.SubjectORegexes,
		"subject_ou_regexes": policy.SubjectOURegexes,
		"subject_st_regexes": policy.SubjectSTRegexes,
		"subject_l_regexes":  policy.SubjectLRegexes,
		"subject_c_regexes":  policy.SubjectCRegexes,
		//"key_type": policy.KeyType,
		//"key_sizes": policy.KeySizes,
		//"key_curves": policy.KeyCurves,
		"dns_san_regexes":   policy.DnsSanRegExs,
		"ip_san_regexes":    policy.IpSanRegExs,
		"email_san_regexes": policy.EmailSanRegExs,
		"uri_san_regexes":   policy.UriSanRegExs,
		"upn_san_regexes":   policy.UpnSanRegExs,
		"allow_wildcards":   policy.AllowWildcards,
		"allow_key_reuse":   policy.AllowKeyReuse,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathUpdateVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {
	name := data.Get("name").(string)

	log.Printf("Write policy endpoint configuration into storage")
	configEntry := &venafiPolicyConfigEntry{
		TPPURL:          data.Get("tpp_url").(string),
		CloudURL:        data.Get("cloud_url").(string),
		Zone:            data.Get("zone").(string),
		TPPPassword:     data.Get("tpp_password").(string),
		Apikey:          data.Get("apikey").(string),
		TPPUser:         data.Get("tpp_user").(string),
		TrustBundleFile: data.Get("trust_bundle_file").(string),
	}
	if configEntry.Apikey == "" && (configEntry.TPPURL == "" || configEntry.TPPUser == "" || configEntry.TPPPassword == "") {
		return logical.ErrorResponse("Invalid mode. apikey or tpp credentials required"), nil
	}
	jsonEntry, err := logical.StorageEntryJSON("venafi-policy/"+name, configEntry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}
	log.Printf("Geting policy from zone %s", data.Get("zone").(string))
	policy, err := b.getPolicyFromVenafi(ctx, req, data.Get("zone").(string), name)

	//Form policy entry for storage
	policyEntry := &venafiPolicyEntry{
		SubjectCNRegexes: policy.SubjectCNRegexes,
		SubjectORegexes:  policy.SubjectORegexes,
		SubjectOURegexes: policy.SubjectOURegexes,
		SubjectSTRegexes: policy.SubjectSTRegexes,
		SubjectLRegexes:  policy.SubjectLRegexes,
		SubjectCRegexes:  policy.SubjectCRegexes,
		//TODO: parse and write key configuration
		//KeyType: policy.AllowedKeyConfigurations[KeyType],
		//KeySizes: policy.AllowedKeyConfigurations[KeySizes],
		//KeyCurves: policy.AllowedKeyConfigurations[KeyCurves],
		DnsSanRegExs:   policy.DnsSanRegExs,
		IpSanRegExs:    policy.IpSanRegExs,
		EmailSanRegExs: policy.EmailSanRegExs,
		UriSanRegExs:   policy.UriSanRegExs,
		UpnSanRegExs:   policy.UpnSanRegExs,
		AllowWildcards: policy.AllowWildcards,
		AllowKeyReuse:  policy.AllowKeyReuse,
	}

	log.Printf("Saving policy into Vault storage")
	jsonEntry, err = logical.StorageEntryJSON("venafi-policy/"+name+"/policy", policyEntry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{"status":"Venafi policy configured successfully"},
	}, nil
}

func (b *backend) getPolicyFromVenafi(ctx context.Context, req *logical.Request, zone string, policyConfig string) (policy *endpoint.Policy, err error) {

	log.Printf("Creating Venafi client")
	cl, err := b.ClientVenafi(ctx, req.Storage, req, policyConfig, "policy")
	if err != nil {
		return policy, err
	}

	log.Printf("Getting policy from Venafi endpoint")
	policy, err = cl.ReadPolicyConfiguration(zone)
	if err != nil {
		return policy, err
	}

	return policy, nil
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
	//if "data-bundle" != "policy-checks" {
	//	return errutil.UserError{Err: fmt.Sprintf(
	//		"Not implemented yet")}
	//}
	return nil
}

func (b *backend) getPolicyConfig(ctx context.Context, s logical.Storage, n string) (*venafiPolicyConfigEntry, error) {
	entry, err := s.Get(ctx, "venafi-policy/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result venafiPolicyConfigEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

type venafiPolicyConfigEntry struct {
	TPPURL          string `json:"tpp_url"`
	Zone            string `json:"zone"`
	TPPPassword     string `json:"tpp_password"`
	TPPUser         string `json:"tpp_user"`
	TPPImport       bool   `json:"tpp_import"`
	TrustBundleFile string `json:"trust_bundle_file"`
	Apikey          string `json:"apikey"`
	CloudURL        string `json:"cloud_url"`
}

type venafiPolicyEntry struct {
	SubjectCNRegexes []string `json:"subject_cn_regexes"`
	SubjectORegexes  []string `json:"subject_or_egexes"`
	SubjectOURegexes []string `json:"subject_ou_regexes"`
	SubjectSTRegexes []string `json:"subject_st_regexes"`
	SubjectLRegexes  []string `json:"subject_l_regexes"`
	SubjectCRegexes  []string `json:"subject_c_regexes"`
	KeyType          []string `json:"key_type"`
	KeySizes         []int    `json:"key_sizes"`
	KeyCurves        []string `json:"key_curves"`
	DnsSanRegExs     []string `json:"dns_san_regexes"`
	IpSanRegExs      []string `json:"ip_san_regexes"`
	EmailSanRegExs   []string `json:"email_san_regexes"`
	UriSanRegExs     []string `json:"uri_san_regexes"`
	UpnSanRegExs     []string `json:"upn_san_regexes"`
	AllowWildcards   bool     `json:"allow_wildcards"`
	AllowKeyReuse    bool     `json:"allow_key_reuse"`
}

const pathVenafiPolicySyn = `help here`
const pathVenafiPolicyDesc = `description here`
