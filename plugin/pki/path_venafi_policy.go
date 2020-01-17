package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
	"strings"
)

const venafiPolicyPath = "venafi-policy/"
const defaultVenafiPolicyName = "default"

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
				Description: `URL of Venafi Platform. Example: https://tpp.venafi.example/vedsdk`,
				Required:    true,
			},
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platform or Cloud policy. 
Example for Platform: testpolicy\\vault
Example for Venafi Cloud: Default`,
				Default: `Default`,
			},
			"tpp_user": {
				Type:        framework.TypeString,
				Description: `web API user for Venafi Platform Example: admin`,
				Required:    true,
			},
			"tpp_password": {
				Type:        framework.TypeString,
				Description: `Password for web API user Example: password`,
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
				Description: `A comma-separated string or list of allowed extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
Also you can use constants from this module (like 1, 5,8) direct or use OIDs (like 1.3.6.1.5.5.7.3.4)`,
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
			logical.ReadOperation:   b.pathReadVenafiPolicyContent,
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
		venafiConnectionConfig: venafiConnectionConfig{
			TPPURL:          data.Get("tpp_url").(string),
			CloudURL:        data.Get("cloud_url").(string),
			Zone:            data.Get("zone").(string),
			TPPPassword:     data.Get("tpp_password").(string),
			Apikey:          data.Get("apikey").(string),
			TPPUser:         data.Get("tpp_user").(string),
			TrustBundleFile: data.Get("trust_bundle_file").(string),
		},
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
	if err != nil {
		return nil, err
	}
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
	cl, err := b.ClientVenafi(ctx, req.Storage, policyConfig, "policy")
	if err != nil {
		return
	}

	log.Printf("Getting policy from Venafi endpoint")

	policy, err = cl.ReadPolicyConfiguration()
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
	if err != nil {
		return nil, err
	}
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
	req *logical.Request,
	role *roleEntry,
	isCA bool,
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

	if csr != nil {
		log.Printf("Checking CSR against policy %s", policyConfigPath)
		if isCA {
			if len(csr.EmailAddresses) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if csr.DNSNames[0] != csr.Subject.CommonName {
					return fmt.Errorf("CA doesn`t allowed to have any SANs: %v, %v, %v, %v", csr.EmailAddresses, csr.DNSNames, csr.IPAddresses, csr.URIs)
				}
			}
		} else {
			if !checkStringByRegexp(csr.Subject.CommonName, policy.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(csr.EmailAddresses, policy.EmailSanRegExs, true) {
				return fmt.Errorf("emails %v doesn't match regexps: %v", email, policy.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(csr.DNSNames, policy.DnsSanRegExs, true) {
				return fmt.Errorf("DNS sans %v doesn't match regexps: %v", csr.DNSNames, policy.DnsSanRegExs)
			}
			ips := make([]string, len(csr.IPAddresses))
			for i, ip := range csr.IPAddresses {
				ips[i] = ip.String()
			}
			if !checkStringArrByRegexp(ips, policy.IpSanRegExs, true) {
				return fmt.Errorf("IPs %v doesn't match regexps: %v", ipAddresses, policy.IpSanRegExs)
			}
			uris := make([]string, len(csr.URIs))
			for i, uri := range csr.URIs {
				uris[i] = uri.String()
			}
			if !checkStringArrByRegexp(uris, policy.UriSanRegExs, true) {
				return fmt.Errorf("URIs %v doesn't match regexps: %v", uris, policy.UriSanRegExs)
			}
		}
		if !checkStringArrByRegexp(csr.Subject.Organization, policy.SubjectORegexes, false) {
			return fmt.Errorf("Organization %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.OrganizationalUnit, policy.SubjectOURegexes, false) {
			return fmt.Errorf("Organization Unit %v doesn't match regexps: %v", csr.Subject.OrganizationalUnit, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Country, policy.SubjectCRegexes, false) {
			return fmt.Errorf("Country %v doesn't match regexps: %v", csr.Subject.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Locality, policy.SubjectLRegexes, false) {
			return fmt.Errorf("Location %v doesn't match regexps: %v", csr.Subject.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Province, policy.SubjectSTRegexes, false) {
			return fmt.Errorf("State (Province) %v doesn't match regexps: %v", csr.Subject.Province, policy.SubjectSTRegexes)
		}
		keyValid := true
		if csr.PublicKeyAlgorithm == x509.RSA {
			pubkey, ok := csr.PublicKey.(*rsa.PublicKey)
			if ok {
				keyValid = checkKey("rsa", pubkey.Size()*8, "", policy.AllowedKeyConfigurations)
			} else {
				log.Println("invalid key in csr")
			}
		} else if csr.PublicKeyAlgorithm == x509.ECDSA {
			pubkey, ok := csr.PublicKey.(*ecdsa.PublicKey)
			if ok {
				keyValid = checkKey("ecdsa", 0, pubkey.Curve.Params().Name, policy.AllowedKeyConfigurations)
			}
		}
		if !keyValid {
			return fmt.Errorf("key type not compatible vith Venafi policies")
		}
	} else {
		log.Printf("Checking creation bundle against policy %s", policyConfigPath)

		if isCA {
			if len(email) != 0 || len(sans) != 0 || len(ipAddresses) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if sans[0] != cn {
					return fmt.Errorf("CA doesn`t allowed to have any SANs: %v, %v, %v", email, sans, ipAddresses)
				}
			}
		} else {
			if !checkStringByRegexp(cn, policy.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(email, policy.EmailSanRegExs, true) {
				return fmt.Errorf("emails %v doesn't match regexps: %v", email, policy.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(sans, policy.DnsSanRegExs, true) {
				return fmt.Errorf("DNS sans %v doesn't match regexps: %v", sans, policy.DnsSanRegExs)
			}
			if !checkStringArrByRegexp(ipAddresses, policy.IpSanRegExs, true) {
				return fmt.Errorf("IPs %v doesn't match regexps: %v", ipAddresses, policy.IpSanRegExs)
			}
		}

		if !checkStringArrByRegexp(role.Organization, policy.SubjectORegexes, false) {
			return fmt.Errorf("Organization %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(role.OU, policy.SubjectOURegexes, false) {
			return fmt.Errorf("Organization Unit %v doesn't match regexps: %v", role.OU, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(role.Country, policy.SubjectCRegexes, false) {
			return fmt.Errorf("Country %v doesn't match regexps: %v", role.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(role.Locality, policy.SubjectLRegexes, false) {
			return fmt.Errorf("Location %v doesn't match regexps: %v", role.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(role.Province, policy.SubjectSTRegexes, false) {
			return fmt.Errorf("State (Province) %v doesn't match regexps: %v", role.Province, policy.SubjectSTRegexes)
		}
		if !checkKey(role.KeyType, role.KeyBits, ecdsaCurvesSizesToName(role.KeyBits), policy.AllowedKeyConfigurations) {
			return fmt.Errorf("key type not compatible vith Venafi policies")
		}

	}

	//TODO: check against upn_san_regexes

	extKeyUsage, err := parseExtKeyUsageParameter(role.ExtKeyUsage)
	if err != nil {
		return err
	}
	if !isCA {
		if !compareEkuList(extKeyUsage, policyConfig.ExtKeyUsage) {
			return fmt.Errorf("different eku in Venafi policy config and role")
		}
	}

	return nil
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

type venafiPolicyConfigEntry struct {
	venafiConnectionConfig
	ExtKeyUsage []x509.ExtKeyUsage `json:"ext_key_usage"`
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
