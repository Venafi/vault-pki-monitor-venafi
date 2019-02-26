package pki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
	"regexp"
	"strings"
)

const venafiPolicyPath = "venafi-policy/" //todo:move over constants here
const defaultVenafiPolicyName = "default"

// This returns the list of queued for import to TPP certificates
func pathVenafiPolicy(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiPolicyPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
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
			"ext_key_usage": {
				Type:    framework.TypeCommaStringSlice,
				Default: []string{},
				Description: `A comma-separated string or list of extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
To remove all key usages from being set, set
this value to an empty list.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathUpdateVenafiPolicy,
			logical.ReadOperation:   b.pathReadVenafiPolicy,
			logical.DeleteOperation: b.pathDeleteVenafiPolicy,
		},

		HelpSynopsis:    pathVenafiPolicySyn,
		HelpDescription: pathVenafiPolicyDesc,
	}
	return ret
}

func pathVenafiPolicyContent(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiPolicyPath + framework.GenericNameRegex("name") + "/policy",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Venafi policy config",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathReadVenafiPolicyContent,
			//TODO: add logical.UpdateOperation which will get policy update from Venafi
			logical.UpdateOperation: b.pathUpdateVenafiPolicyContent,
		},

		HelpSynopsis:    pathVenafiPolicySyn,
		HelpDescription: pathVenafiPolicyDesc,
	}
	return ret
}

func pathVenafiPolicyList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiPolicyPath,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathListVenafiPolicy,
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
}

func (b *backend) pathReadVenafiPolicyContent(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	log.Printf("Trying to read policy for config %s", name)

	if len(name) == 0 {
		return logical.ErrorResponse("Non config specified or wrong config path name"), nil
	}

	entry, err := req.Storage.Get(ctx, venafiPolicyPath+name+"/policy")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("policy data is nil. Looks like it doesn't exists."), nil
	}

	var policy venafiPolicyEntry
	if err := entry.DecodeJSON(&policy); err != nil {
		log.Printf("error reading Venafi policy configuration: %s", err)
		return nil, err
	}

	//Send policy to the user output
	respData := formPolicyRespData(policy)

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathUpdateVenafiPolicyContent(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	policy, err := b.getPolicyFromVenafi(ctx, req, name)
	if err != nil {
		return nil, err
	}

	policyEntry, err := savePolicyEntry(policy, name, ctx, req)
	if err != nil {
		return nil, err
	}

	respData := formPolicyRespData(*policyEntry)
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
	unparsedKeyUsage := data.Get("ext_key_usage").([]string)
	configEntry.ExtKeyUsage, err = parseExtKeyUsageParameter(unparsedKeyUsage)
	if err != nil {
		return
	}
	if configEntry.Apikey == "" && (configEntry.TPPURL == "" || configEntry.TPPUser == "" || configEntry.TPPPassword == "") {
		return logical.ErrorResponse("Invalid mode. apikey or tpp credentials required"), nil
	}
	jsonEntry, err := logical.StorageEntryJSON(venafiPolicyPath+name, configEntry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}
	log.Printf("Geting policy from zone %s", data.Get("zone").(string))
	policy, err := b.getPolicyFromVenafi(ctx, req, name)
	if err != nil {
		return nil, err
	}
	policyEntry, err := savePolicyEntry(policy, name, ctx, req)
	//Send policy to the user output
	respData := formPolicyRespData(*policyEntry)

	return &logical.Response{
		Data: respData,
	}, nil
}

func savePolicyEntry(policy *endpoint.Policy, name string, ctx context.Context, req *logical.Request) (policyEntry *venafiPolicyEntry, err error) {

	//Form policy entry for storage
	policyEntry = &venafiPolicyEntry{
		SubjectCNRegexes:         policy.SubjectCNRegexes,
		SubjectORegexes:          policy.SubjectORegexes,
		SubjectOURegexes:         policy.SubjectOURegexes,
		SubjectSTRegexes:         policy.SubjectSTRegexes,
		SubjectLRegexes:          policy.SubjectLRegexes,
		SubjectCRegexes:          policy.SubjectCRegexes,
		AllowedKeyConfigurations: policy.AllowedKeyConfigurations,
		DnsSanRegExs:             policy.DnsSanRegExs,
		IpSanRegExs:              policy.IpSanRegExs,
		EmailSanRegExs:           policy.EmailSanRegExs,
		UriSanRegExs:             policy.UriSanRegExs,
		UpnSanRegExs:             policy.UpnSanRegExs,
		AllowWildcards:           policy.AllowWildcards,
		AllowKeyReuse:            policy.AllowKeyReuse,
	}

	log.Printf("Saving policy into Vault storage")
	jsonEntry, err := logical.StorageEntryJSON(venafiPolicyPath+name+"/policy", policyEntry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return policyEntry, nil
}

func formPolicyRespData(policy venafiPolicyEntry) (respData map[string]interface{}) {
	type printKeyConfig struct {
		KeyType   string
		KeySizes  []int    `json:",omitempty"`
		KeyCurves []string `json:",omitempty"`
	}
	keyConfigs := make([]string, len(policy.AllowedKeyConfigurations))
	for i, akc := range policy.AllowedKeyConfigurations {
		kc := printKeyConfig{akc.KeyType.String(), akc.KeySizes, nil}
		if akc.KeyType == certificate.KeyTypeECDSA {
			kc.KeyCurves = make([]string, len(akc.KeyCurves))
			for i, c := range akc.KeyCurves {
				kc.KeyCurves[i] = c.String()
			}
		}
		kb, _ := json.Marshal(kc)
		keyConfigs[i] = string(kb)
	}
	return map[string]interface{}{
		"subject_cn_regexes":         policy.SubjectCNRegexes,
		"subject_or_regexes":         policy.SubjectORegexes,
		"subject_ou_regexes":         policy.SubjectOURegexes,
		"subject_st_regexes":         policy.SubjectSTRegexes,
		"subject_l_regexes":          policy.SubjectLRegexes,
		"subject_c_regexes":          policy.SubjectCRegexes,
		"allowed_key_configurations": keyConfigs,
		"dns_san_regexes":            policy.DnsSanRegExs,
		"ip_san_regexes":             policy.IpSanRegExs,
		"email_san_regexes":          policy.EmailSanRegExs,
		"uri_san_regexes":            policy.UriSanRegExs,
		"upn_san_regexes":            policy.UpnSanRegExs,
		"allow_wildcards":            policy.AllowWildcards,
		"allow_key_reuse":            policy.AllowKeyReuse,
	}
}

func (b *backend) getPolicyFromVenafi(ctx context.Context, req *logical.Request, policyConfig string) (policy *endpoint.Policy, err error) {
	log.Printf("Creating Venafi client")
	cl, err := b.ClientVenafi(ctx, req.Storage, req, policyConfig, "policy")
	if err != nil {
		return
	}

	log.Printf("Getting policy from Venafi endpoint")
	zone, err := b.getPolicyConfigZone(ctx, req.Storage, policyConfig)
	if err != nil {
		return
	}

	policy, err = cl.ReadPolicyConfiguration(zone)
	if err != nil {
		return
	}
	if policy == nil {
		err = fmt.Errorf("expected policy but got nil from Venafi endpoint %v", policy)
		return
	}

	return
}

func (b *backend) pathReadVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	name := data.Get("name").(string)
	log.Printf("Trying to read policy for config %s", name)

	if len(name) == 0 {
		return logical.ErrorResponse("Non config specified or wrong config path name"), nil
	}

	entry, err := req.Storage.Get(ctx, venafiPolicyPath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return logical.ErrorResponse("policy config is nil. Looks like it doesn't exists."), nil
	}

	var config venafiPolicyConfigEntry

	if err := entry.DecodeJSON(&config); err != nil {
		log.Printf("error reading Venafi policy configuration: %s", err)
		return nil, err
	}

	//Send config to the user output
	respData := map[string]interface{}{
		"tpp_url":           config.TPPURL,
		"zone":              config.Zone,
		"tpp_password":      config.TPPPassword,
		"tpp_user":          config.TPPUser,
		"tpp_import":        config.TPPImport,
		"trust_bundle_file": config.TrustBundleFile,
		"apikey":            config.Apikey,
		"cloud_url":         config.CloudURL,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathDeleteVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)
	rawEntry, err := req.Storage.List(ctx, venafiPolicyPath+name+"/")
	//Deleting all content of the policy
	for _, e := range rawEntry {
		err = req.Storage.Delete(ctx, venafiPolicyPath+name+"/"+e)
		if err != nil {
			return nil, err
		}
	}

	//Deleting policy path
	err = req.Storage.Delete(ctx, venafiPolicyPath+name)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathListVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	policies, err := req.Storage.List(ctx, venafiPolicyPath)
	var entries []string
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		//Removing from policy list repeated policy name with / at the end
		if !strings.Contains(policy, "/") {
			entries = append(entries, policy)
		}

	}
	return logical.ListResponse(entries), nil
}

func checkAgainstVenafiPolicy(
	b *backend,
	req *logical.Request,
	role *roleEntry,
	csr *x509.CertificateRequest,
	cn string,
	ipAddresses, email, sans []string) error {

	policyConfigPath := role.VenafiCheckPolicy
	ctx := context.Background()
	if policyConfigPath == "" {
		policyConfigPath = defaultVenafiPolicyName
	}

	entry, err := req.Storage.Get(ctx, venafiPolicyPath+policyConfigPath+"/policy")
	if err != nil {
		return err
	}
	if entry == nil {
		if venafiPolicyDenyAll {
			if strings.Contains(req.Path, "root/generate") {
				//internal certificate won't output error response
				log.Println("policy data is nil. You need configure Venafi policy to proceed")
			}
			return fmt.Errorf("policy data is nil. You need configure Venafi policy to proceed")
		} else {
			return nil
		}
	}

	var policy venafiPolicyEntry

	if err := entry.DecodeJSON(&policy); err != nil {
		log.Printf("error reading Venafi policy configuration: %s", err)
		return err
	}
	entry, err = req.Storage.Get(ctx, venafiPolicyPath+policyConfigPath)
	if err != nil {
		return err
	}
	var policyConfig venafiPolicyConfigEntry
	if err := entry.DecodeJSON(&policyConfig); err != nil {
		log.Printf("error reading Venafi policy configuration: %s", err)
		return err
	}
	log.Printf("Checking creation bundle against policy %s", policyConfigPath)

	if !checkStringByRegexp(cn, policy.SubjectCNRegexes) {
		return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
	}
	if !checkStringArrByRegexp(email, policy.EmailSanRegExs) {
		return fmt.Errorf("Emails %v doesn't match regexps: %v", email, policy.EmailSanRegExs)
	}
	if !checkStringArrByRegexp(sans, policy.DnsSanRegExs) {
		return fmt.Errorf("DNS sans %v doesn't match regexps: %v", sans, policy.DnsSanRegExs)
	}
	if !checkStringArrByRegexp(ipAddresses, policy.IpSanRegExs) {
		return fmt.Errorf("IPs %v doesn't match regexps: %v", ipAddresses, policy.IpSanRegExs)
	}

	//TODO: check against data.csr because we also have path /sign (func pathSign) which is using CSR.
	if csr != nil {
		log.Printf("Checking CSR against policy %s", policyConfigPath)

		if !checkStringByRegexp(csr.Subject.CommonName, policy.SubjectCNRegexes) {
			return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
		}
		if !checkStringArrByRegexp(csr.EmailAddresses, policy.EmailSanRegExs) {
			return fmt.Errorf("Emails %v doesn't match regexps: %v", email, policy.EmailSanRegExs)
		}
		if !checkStringArrByRegexp(csr.DNSNames, policy.DnsSanRegExs) {
			return fmt.Errorf("DNS sans %v doesn't match regexps: %v", sans, policy.DnsSanRegExs)
		}
		//TODO: parse IP to string
		//if !checkStringArrByRegexp(csr.IPAddresses, policy.IpSanRegExs) {
		//	return fmt.Errorf("IPs %v doesn't match regexps: %v", ipAddresses, policy.IpSanRegExs)
		//}

		if !checkStringArrByRegexp(csr.Subject.Organization, policy.SubjectOURegexes) {
			return fmt.Errorf("Organization unit %v doesn't match regexps: %v", role.Organization, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.OrganizationalUnit, policy.SubjectORegexes) {
			return fmt.Errorf("Organization Unit %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Country, policy.SubjectCRegexes) {
			return fmt.Errorf("Country %v doesn't match regexps: %v", role.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Locality, policy.SubjectLRegexes) {
			return fmt.Errorf("Location %v doesn't match regexps: %v", role.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Province, policy.SubjectSTRegexes) {
			return fmt.Errorf("State (Province) %v doesn't match regexps: %v", role.Locality, policy.SubjectLRegexes)
		}
	} else {
		log.Printf("Checking creation bundle against policy %s", policyConfigPath)
		if !checkStringArrByRegexp(role.Organization, policy.SubjectOURegexes) {
			return fmt.Errorf("Organization unit %v doesn't match regexps: %v", role.Organization, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(role.OU, policy.SubjectORegexes) {
			return fmt.Errorf("Organization Unit %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(role.Country, policy.SubjectCRegexes) {
			return fmt.Errorf("Country %v doesn't match regexps: %v", role.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(role.Locality, policy.SubjectLRegexes) {
			return fmt.Errorf("Location %v doesn't match regexps: %v", role.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(role.Province, policy.SubjectSTRegexes) {
			return fmt.Errorf("State (Province) %v doesn't match regexps: %v", role.Locality, policy.SubjectLRegexes)
		}

	}

	//TODO: check against upn_san_regexes
	//TODO: check against uri_san_regexes
	//todo: add suuport csr
	if !checkKey(role.KeyType, role.KeyBits, policy.AllowedKeyConfigurations) {
		return fmt.Errorf("key type not compatible vith Venafi policies")
	}

	extKeyUsage, err := parseExtKeyUsageParameter(role.ExtKeyUsage)
	if err != nil {
		return err
	}
	//todo: need skip this check for CA or adopt checking for ca
	if !compareEkuList(extKeyUsage, policyConfig.ExtKeyUsage) {
		return fmt.Errorf("different eku in Venafi policy config and role")
	}

	return nil
}

func checkKey(keyType string, bitsize int, allowed []endpoint.AllowedKeyConfiguration) bool {
	//todo: write
	return true
}

func checkStringByRegexp(s string, regexs []string) (matched bool) {
	var err error
	for _, r := range regexs {
		matched, err = regexp.MatchString(r, s)
		if err == nil && matched {
			return true
		}
	}
	return
}

func checkStringArrByRegexp(ss []string, regexs []string) (matched bool) {
	for _, s := range ss {
		if !checkStringByRegexp(s, regexs) {
			return false
		}
	}
	return true
}

func (b *backend) getPolicyConfig(ctx context.Context, s logical.Storage, n string) (*venafiPolicyConfigEntry, error) {
	entry, err := s.Get(ctx, venafiPolicyPath+n)
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

func (b *backend) getPolicyConfigZone(ctx context.Context, s logical.Storage, n string) (string, error) {
	entry, err := s.Get(ctx, venafiPolicyPath+n)
	if err != nil {
		return "", err
	}
	if entry == nil {
		return "", nil
	}

	var result venafiPolicyConfigEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return "", err
	}
	zone := result.Zone
	return zone, nil
}

type venafiPolicyConfigEntry struct {
	TPPURL          string             `json:"tpp_url"`
	Zone            string             `json:"zone"`
	TPPPassword     string             `json:"tpp_password"`
	TPPUser         string             `json:"tpp_user"`
	TPPImport       bool               `json:"tpp_import"`
	TrustBundleFile string             `json:"trust_bundle_file"`
	Apikey          string             `json:"apikey"`
	CloudURL        string             `json:"cloud_url"`
	ExtKeyUsage     []x509.ExtKeyUsage `json:"ext_key_usage"`
}

type venafiPolicyEntry struct {
	SubjectCNRegexes         []string                           `json:"subject_cn_regexes"`
	SubjectORegexes          []string                           `json:"subject_or_regexes"`
	SubjectOURegexes         []string                           `json:"subject_ou_regexes"`
	SubjectSTRegexes         []string                           `json:"subject_st_regexes"`
	SubjectLRegexes          []string                           `json:"subject_l_regexes"`
	SubjectCRegexes          []string                           `json:"subject_c_regexes"`
	AllowedKeyConfigurations []endpoint.AllowedKeyConfiguration `json:"allowed_key_configurations"`
	DnsSanRegExs             []string                           `json:"dns_san_regexes"`
	IpSanRegExs              []string                           `json:"ip_san_regexes"`
	EmailSanRegExs           []string                           `json:"email_san_regexes"`
	UriSanRegExs             []string                           `json:"uri_san_regexes"`
	UpnSanRegExs             []string                           `json:"upn_san_regexes"`
	AllowWildcards           bool                               `json:"allow_wildcards"`
	AllowKeyReuse            bool                               `json:"allow_key_reuse"`
}

const pathVenafiPolicySyn = `help here`
const pathVenafiPolicyDesc = `description here`
