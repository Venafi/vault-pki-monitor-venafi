package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"regexp"
	"strings"
)

const (
	venafiRolePolicyMapStorage  = "venafi-role-policy-map"
	venafiPolicyPath            = "venafi-policy/"
	defaultVenafiPolicyName     = "default"
	policyFieldEnforcementRoles = "enforcement_roles"
	policyFieldDefaultsRoles    = "defaults_roles"
	policyFieldImportRoles      = "import_roles"
	policyFieldCreateRole       = "create_role"
	venafiRolePolicyMapPath     = "show-venafi-role-policy-map"
	errPolicyMapDoesNotExists   = "policy map does not exists"
)

func pathVenafiPolicy(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiPolicyPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Venafi policy config",
			},
			"ext_key_usage": {
				Type:    framework.TypeCommaStringSlice,
				Default: []string{},
				Description: `A comma-separated string or list of allowed extended key usages. Valid values can be found at
https://golang.org/pkg/crypto/x509/#ExtKeyUsage
-- simply drop the "ExtKeyUsage" part of the name.
Also you can use constants from this module (like 1, 5,8) direct or use OIDs (like 1.3.6.1.5.5.7.3.4)`,
			},
			"auto_refresh_interval": {
				Type:        framework.TypeInt,
				Default:     0,
				Description: `Interval of policy update from Venafi in seconds. Set it to 0 to disable automatic policy update`,
			},
			policyFieldEnforcementRoles: {
				Type:        framework.TypeCommaStringSlice,
				Default:     []string{},
				Description: "Roles list for policy check",
			},
			policyFieldDefaultsRoles: {
				Type:        framework.TypeCommaStringSlice,
				Default:     []string{},
				Description: "Roles list for filing with default values from Venafi",
			},
			policyFieldImportRoles: {
				Type:        framework.TypeCommaStringSlice,
				Default:     []string{},
				Description: "Roles list for import to Venafi",
			},
			"import_timeout": {
				Type:        framework.TypeInt,
				Default:     15,
				Description: `Timeout in second to rerun import queue`,
			},
			"import_workers": {
				Type:        framework.TypeInt,
				Default:     5,
				Description: `Max amount of simultaneously working instances of vcert import`,
			},
			"import_only_non_compliant": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Only import certificates into Venafi that do not comply with zone policy",
			},
			policyFieldCreateRole: {
				Type:        framework.TypeBool,
				Default:     false,
				Description: `Automatically create empty role for policy if it does not exists`,
			},
			"venafi_secret": {
				Type:        framework.TypeString,
				Description: `The name of the credentials object to be used for authentication`,
				Required:    true,
			},
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platform or Cloud policy. 
Example for Platform: testPolicy\\vault
Example for Venafi Cloud: Default`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateVenafiPolicy,
				Summary:  "Configure the settings of a Venafi policy",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadVenafiPolicy,
				Summary:  "Return the Venafi policy specified in path",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteVenafiPolicy,
				Summary:  "Removes the Venafi policy specified in path",
			},
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
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadVenafiPolicyContent,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateVenafiPolicyContent,
			},
		},

		HelpSynopsis:    pathVenafiPolicySyn,
		HelpDescription: pathVenafiPolicyDesc,
	}
	return ret
}

func pathVenafiPolicyList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiPolicyPath,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListVenafiPolicy,
			},
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
}

func pathVenafiPolicyMap(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiRolePolicyMapPath,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathShowVenafiPolicyMap,
			},
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
}

func (b *backend) refreshVenafiPolicyEnforcementContent(storage logical.Storage, policyName string) (err error) {

	ctx := context.Background()

	venafiPolicyConfig, err := b.getVenafiPolicyConfig(ctx, &storage, policyName)
	if err != nil {
		return fmt.Errorf("error getting policy config %s: %s", policyName, err)

	}
	if venafiPolicyConfig == nil {
		return fmt.Errorf("policy config for %s is empty", policyName)
	}

	if venafiPolicyConfig.AutoRefreshInterval > 0 {
		log.Printf("%s Auto refresh enabled for policy %s. Getting policy from Venafi", logPrefixVenafiPolicyEnforcement, policyName)
	} else {
		return nil
	}

	policy, err := b.getPolicyFromVenafi(ctx, &storage, policyName)
	if err != nil {
		return fmt.Errorf("error getting policy %s from Venafi: %s", policyName, err)

	}

	log.Printf("%s Saving policy %s", logPrefixVenafiPolicyEnforcement, policyName)
	_, err = savePolicyEntry(policy, policyName, ctx, &storage)
	if err != nil {
		return fmt.Errorf("%s Error saving policy: %s", logPrefixVenafiPolicyEnforcement, err)

	}
	//policy config's credentials may be got updated so get it from storage again before saving it.
	venafiPolicyConfig, _ = b.getVenafiPolicyConfig(ctx, &storage, policyName)

	jsonEntry, err := logical.StorageEntryJSON(venafiPolicyPath+policyName, venafiPolicyConfig)
	if err != nil {
		return fmt.Errorf("%s Error converting policy config into JSON: %s", logPrefixVenafiPolicyEnforcement, err)

	}
	if err := storage.Put(ctx, jsonEntry); err != nil {
		return fmt.Errorf("error saving policy last update time: %s", err)

	}

	return nil
}

func (b *backend) pathReadVenafiPolicyContent(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	log.Printf("%s Trying to read policy for config %s", logPrefixVenafiPolicyEnforcement, name)

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
		log.Printf("%s error reading Venafi policy configuration: %s", logPrefixVenafiPolicyEnforcement, err)
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

	policy, err := b.getPolicyFromVenafi(ctx, &req.Storage, name)
	if err != nil {
		return nil, err
	}

	policyEntry, err := savePolicyEntry(policy, name, ctx, &req.Storage)
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

	log.Printf("%s Write policy endpoint configuration into storage", logPrefixVenafiPolicyEnforcement)

	venafiPolicyConfig := &venafiPolicyConfigEntry{
		AutoRefreshInterval:    int64(data.Get("auto_refresh_interval").(int)),
		VenafiImportTimeout:    data.Get("import_timeout").(int),
		VenafiImportWorkers:    data.Get("import_workers").(int),
		CreateRole:             data.Get(policyFieldCreateRole).(bool),
		VenafiSecret:           data.Get("venafi_secret").(string),
		Zone:                   data.Get("zone").(string),
		ImportOnlyNonCompliant: data.Get("import_only_non_compliant").(bool),
	}
	unparsedKeyUsage := data.Get("ext_key_usage").([]string)
	venafiPolicyConfig.ExtKeyUsage, err = parseExtKeyUsageParameter(unparsedKeyUsage)
	if err != nil {
		return
	}

	jsonEntry, err := logical.StorageEntryJSON(venafiPolicyPath+name, venafiPolicyConfig)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	log.Printf("%s Geting policy using Venafi secret: %s", logPrefixVenafiPolicyEnforcement, venafiPolicyConfig.VenafiSecret)
	policy, err := b.getPolicyFromVenafi(ctx, &req.Storage, name)
	if err != nil {
		return nil, err
	}
	policyEntry, err := savePolicyEntry(policy, name, ctx, &req.Storage)
	if err != nil {
		return nil, err
	}

	log.Printf("%s Updating roles policy attributes", logPrefixVenafiPolicyEnforcement)

	err = b.updateRolesPolicyAttributes(ctx, req, data, name)
	if err != nil {
		return nil, err
	}

	//Send policy to the user output
	respData := formPolicyRespData(*policyEntry)

	return &logical.Response{
		Data:     respData,
		Warnings: []string{},
	}, nil

}

type policyTypes struct {
	ImportPolicy      string `json:"import_policy"`
	DefaultsPolicy    string `json:"defaults_policy"`
	EnforcementPolicy string `json:"enforcement_policy"`
}

type policyRoleMap struct {
	Roles map[string]policyTypes `json:"roles"`
}

func getPolicyRoleMap(ctx context.Context, storage logical.Storage) (policyMap policyRoleMap, err error) {
	//TODO: write test for it
	policyMap.Roles = make(map[string]policyTypes)

	entry, err := storage.Get(ctx, venafiRolePolicyMapStorage)
	if err != nil {
		return policyMap, err
	}

	if entry == nil {
		return policyMap, fmt.Errorf(errPolicyMapDoesNotExists)
	}

	err = json.Unmarshal(entry.Value, &policyMap)
	if err != nil {
		return policyMap, err
	}

	return policyMap, err
}

func (b *backend) updateRolesPolicyAttributes(ctx context.Context, req *logical.Request, data *framework.FieldData, name string) error {
	//TODO: write test for it

	policyMap, err := getPolicyRoleMap(ctx, req.Storage)
	if err != nil {
		if err.Error() == errPolicyMapDoesNotExists {
			log.Println(errPolicyMapDoesNotExists + " will create new")
		} else {
			return err
		}

	}

	for _, roleType := range []string{policyFieldEnforcementRoles, policyFieldDefaultsRoles, policyFieldImportRoles} {
		for _, roleName := range data.Get(roleType).([]string) {
			role, err := b.getRole(ctx, req.Storage, roleName)
			if err != nil {
				return err
			}
			if role == nil {
				if data.Get(policyFieldCreateRole).(bool) {
					return fmt.Errorf("role %s does not exists. can not add it to the attributes of policy %s", roleName, name)
				} else {
					//TODO: create role here
					log.Println("Creating role", roleName)
				}
			}

			r := policyTypes{}

			//copy policy values before setting new value
			r.EnforcementPolicy = policyMap.Roles[roleName].EnforcementPolicy
			r.DefaultsPolicy = policyMap.Roles[roleName].DefaultsPolicy
			r.ImportPolicy = policyMap.Roles[roleName].ImportPolicy

			switch roleType {
			case policyFieldEnforcementRoles:
				r.EnforcementPolicy = name
			case policyFieldDefaultsRoles:
				r.DefaultsPolicy = name
			case policyFieldImportRoles:
				r.ImportPolicy = name
			}

			policyMap.Roles[roleName] = r

			jsonEntry, err := logical.StorageEntryJSON("role/"+roleName, role)
			if err != nil {
				return err
			}
			if err := req.Storage.Put(ctx, jsonEntry); err != nil {
				return err
			}
		}
	}

	jsonEntry, err := logical.StorageEntryJSON(venafiRolePolicyMapStorage, policyMap)

	if err != nil {
		return err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return err
	}
	return nil
}

func savePolicyEntry(policy *endpoint.Policy, name string, ctx context.Context, storage *logical.Storage) (policyEntry *venafiPolicyEntry, err error) {

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

	log.Printf("%s Saving policy into Vault storage", logPrefixVenafiPolicyEnforcement)
	jsonEntry, err := logical.StorageEntryJSON(venafiPolicyPath+name+"/policy", policyEntry)
	if err != nil {
		return nil, err
	}
	if err := (*storage).Put(ctx, jsonEntry); err != nil {
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
		"subject_o_regexes":          policy.SubjectORegexes,
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

func (b *backend) getPolicyFromVenafi(ctx context.Context, storage *logical.Storage, policyConfig string) (policy *endpoint.Policy, err error) {
	log.Printf("%s Creating Venafi client", logPrefixVenafiPolicyEnforcement)
	cl, err := b.ClientVenafi(ctx, storage, policyConfig)
	if err != nil {
		return
	}
	log.Printf("%s Getting policy from Venafi endpoint", logPrefixVenafiPolicyEnforcement)

	policy, err = cl.ReadPolicyConfiguration()
	if (err != nil) && (cl.GetType() == endpoint.ConnectorTypeTPP) {
		msg := err.Error()

		//catch the scenario when token is expired and deleted.
		var regex = regexp.MustCompile("(expired|invalid)_token")

		//validate if the error is related to a expired access token, at this moment the only way can validate this is using the error message
		//and verify if that message describes errors related to expired access token.
		code := getStatusCode(msg)
		if code == HTTP_UNAUTHORIZED && regex.MatchString(msg) {

			cfg, err := b.getConfig(ctx, storage, policyConfig)

			if err != nil {
				return nil, err
			}

			if cfg.Credentials.RefreshToken != "" {
				err = synchronizedUpdateAccessToken(cfg, b, ctx, storage, policyConfig)

				if err != nil {
					return nil, err
				}

				//everything went fine so get the new client with the new refreshed access token
				cl, err := b.ClientVenafi(ctx, storage, policyConfig)
				if err != nil {
					return nil, err
				}

				b.Logger().Debug("Making certificate request again")

				policy, err = cl.ReadPolicyConfiguration()
				if err != nil {
					return nil, err
				} else {
					return policy, nil
				}
			} else {
				err = fmt.Errorf("tried to get new access token but refresh token is empty")
				return nil, err
			}

		} else {
			return nil, err
		}
	}
	if policy == nil {
		err = fmt.Errorf("expected policy but got nil from Venafi endpoint %v", policy)
		return
	}

	return
}

func (b *backend) pathReadVenafiPolicy(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	name := data.Get("name").(string)
	log.Printf("%s Trying to read policy for config %s", logPrefixVenafiPolicyEnforcement, name)

	if len(name) == 0 {
		return logical.ErrorResponse("No config specified or wrong config path name"), nil
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
		log.Printf("%s error reading Venafi policy configuration: %s", logPrefixVenafiPolicyEnforcement, err)
		return nil, err
	}

	rolesList, err := b.getRolesListForVenafiPolicy(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	//Send config to the user output
	respData := map[string]interface{}{
		"venafi_secret":             config.VenafiSecret,
		"zone":                      config.Zone,
		policyFieldImportRoles:      rolesList.importRoles,
		policyFieldDefaultsRoles:    rolesList.defaultsRoles,
		policyFieldEnforcementRoles: rolesList.enforceRoles,
		"auto_refresh_interval":     config.AutoRefreshInterval,
		"last_policy_update_time":   config.LastPolicyUpdateTime,
		"import_timeout":            config.VenafiImportTimeout,
		"import_workers":            config.VenafiImportWorkers,
		"create_role":               config.CreateRole,
		"import_only_non_compliant": config.ImportOnlyNonCompliant,
	}

	return &logical.Response{
		Data: respData,
	}, nil
}

type rolesListForVenafiPolicy struct {
	importRoles   []string
	enforceRoles  []string
	defaultsRoles []string
}

func (b *backend) getRolesListForVenafiPolicy(ctx context.Context, storage logical.Storage, policyName string) (rolesList rolesListForVenafiPolicy, err error) {

	//In this function we're getting a role list for Venafi policy.
	//Each role have three hidden attributes: VenafiImportPolicy,  VenafiEnforcementPolicy and VenafiDefaultsPolicy
	roles, err := storage.List(ctx, "role/")
	if err != nil {
		return
	}

	policyMap, err := getPolicyRoleMap(ctx, storage)
	if err != nil {
		return
	}
	for _, roleName := range roles {

		//If policy name is in one of role policy attributes append it to the roleList structure
		if policyMap.Roles[roleName].ImportPolicy == policyName {
			rolesList.importRoles = append(rolesList.importRoles, roleName)
		}
		if policyMap.Roles[roleName].EnforcementPolicy == policyName {
			rolesList.enforceRoles = append(rolesList.enforceRoles, roleName)
		}
		if policyMap.Roles[roleName].DefaultsPolicy == policyName {
			rolesList.defaultsRoles = append(rolesList.defaultsRoles, roleName)
		}
	}
	return rolesList, err
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

func (b *backend) pathShowVenafiPolicyMap(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, err error) {
	//TODO: test it!
	entry, err := req.Storage.Get(ctx, venafiRolePolicyMapStorage)
	if err != nil {
		return nil, err
	}

	response = &logical.Response{
		Data: map[string]interface{}{},
	}

	response.Data["policy_map_json"] = entry.Value

	return response, nil
}

func checkAgainstVenafiPolicy(
	req *logical.Request,
	role *roleEntry,
	isCA bool,
	csr *x509.CertificateRequest,
	cn string,
	ipAddresses, email, sans []string) error {

	ctx := context.Background()

	policyMap, err := getPolicyRoleMap(ctx, req.Storage)
	if err != nil {
		return err
	}

	venafiEnforcementPolicy := policyMap.Roles[role.Name].EnforcementPolicy
	if venafiEnforcementPolicy == "" && venafiPolicyDenyAll{
		venafiEnforcementPolicy = defaultVenafiPolicyName
	}

	entry, err := req.Storage.Get(ctx, venafiPolicyPath+venafiEnforcementPolicy+"/policy")
	if err != nil {
		return err
	}
	if entry == nil {
		if venafiPolicyDenyAll {
			//TODO: Can not understand why I added this if here. Probably should be removed
			//if strings.Contains(req.Path, "root/generate") {
			//	log.Println("policy data is nil. You need configure Venafi policy to proceed")
			//}
			return fmt.Errorf("policy data is nil. You need configure Venafi policy to proceed")
		} else {
			return nil
		}
	}

	var policy venafiPolicyEntry

	if err := entry.DecodeJSON(&policy); err != nil {
		log.Printf("%s error reading Venafi policy configuration: %s", logPrefixVenafiPolicyEnforcement, err)
		return err
	}
	entry, err = req.Storage.Get(ctx, venafiPolicyPath+venafiEnforcementPolicy)
	if err != nil {
		return err
	}
	var policyConfig venafiPolicyConfigEntry
	if err := entry.DecodeJSON(&policyConfig); err != nil {
		log.Printf("%s error reading Venafi policy configuration: %s", logPrefixVenafiPolicyEnforcement, err)
		return err
	}

	if csr != nil {
		log.Printf("%s Checking CSR against policy %s", logPrefixVenafiPolicyEnforcement, venafiEnforcementPolicy)
		if isCA {
			if len(csr.EmailAddresses) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if csr.DNSNames[0] != csr.Subject.CommonName {
					return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v, %v", csr.EmailAddresses, csr.DNSNames, csr.IPAddresses, csr.URIs)
				}
			}
		} else {
			if !checkStringByRegexp(csr.Subject.CommonName, policy.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(csr.EmailAddresses, policy.EmailSanRegExs, true) {
				return fmt.Errorf("email SANs %v do not match regexps: %v", email, policy.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(csr.DNSNames, policy.DnsSanRegExs, true) {
				return fmt.Errorf("DNS SANs %v do not match regexps: %v", csr.DNSNames, policy.DnsSanRegExs)
			}
			ips := make([]string, len(csr.IPAddresses))
			for i, ip := range csr.IPAddresses {
				ips[i] = ip.String()
			}
			if !checkStringArrByRegexp(ips, policy.IpSanRegExs, true) {
				return fmt.Errorf("IP SANs %v do not match regexps: %v", ipAddresses, policy.IpSanRegExs)
			}
			uris := make([]string, len(csr.URIs))
			for i, uri := range csr.URIs {
				uris[i] = uri.String()
			}
			if !checkStringArrByRegexp(uris, policy.UriSanRegExs, true) {
				return fmt.Errorf("URI SANs %v do not match regexps: %v", uris, policy.UriSanRegExs)
			}
		}
		if !checkStringArrByRegexp(csr.Subject.Organization, policy.SubjectORegexes, false) {
			return fmt.Errorf("organization %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.OrganizationalUnit, policy.SubjectOURegexes, false) {
			return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", csr.Subject.OrganizationalUnit, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Country, policy.SubjectCRegexes, false) {
			return fmt.Errorf("country %v doesn't match regexps: %v", csr.Subject.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Locality, policy.SubjectLRegexes, false) {
			return fmt.Errorf("city (locality) %v doesn't match regexps: %v", csr.Subject.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(csr.Subject.Province, policy.SubjectSTRegexes, false) {
			return fmt.Errorf("state (province) %v doesn't match regexps: %v", csr.Subject.Province, policy.SubjectSTRegexes)
		}
		keyValid := true
		if csr.PublicKeyAlgorithm == x509.RSA {
			pubKey, ok := csr.PublicKey.(*rsa.PublicKey)
			if ok {
				keyValid = checkKey("rsa", pubKey.Size()*8, "", policy.AllowedKeyConfigurations)
			} else {
				log.Printf("%s invalid key in CSR", logPrefixVenafiPolicyEnforcement)
			}
		} else if csr.PublicKeyAlgorithm == x509.ECDSA {
			pubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
			if ok {
				keyValid = checkKey("ecdsa", 0, pubKey.Curve.Params().Name, policy.AllowedKeyConfigurations)
			}
		}
		if !keyValid {
			return fmt.Errorf("key type is not allowed by Venafi policies")
		}
	} else {
		log.Printf("%s Checking creation bundle against policy %s", logPrefixVenafiPolicyEnforcement, venafiEnforcementPolicy)

		if isCA {
			if len(email) != 0 || len(sans) != 0 || len(ipAddresses) != 0 {
				//workaround for setting SAN if CA have normal domain in CN
				if sans[0] != cn {
					return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v", email, sans, ipAddresses)
				}
			}
		} else {
			if !checkStringByRegexp(cn, policy.SubjectCNRegexes) {
				return fmt.Errorf("common name %s doesn't match regexps: %v", cn, policy.SubjectCNRegexes)
			}
			if !checkStringArrByRegexp(email, policy.EmailSanRegExs, true) {
				return fmt.Errorf("email SANs %v do not match regexps: %v", email, policy.EmailSanRegExs)
			}
			if !checkStringArrByRegexp(sans, policy.DnsSanRegExs, true) {
				return fmt.Errorf("DNS SANs %v do not match regexps: %v", sans, policy.DnsSanRegExs)
			}
			if !checkStringArrByRegexp(ipAddresses, policy.IpSanRegExs, true) {
				return fmt.Errorf("IP SANs %v do not match regexps: %v", ipAddresses, policy.IpSanRegExs)
			}
		}

		if !checkStringArrByRegexp(role.Organization, policy.SubjectORegexes, false) {
			return fmt.Errorf("organization %v doesn't match regexps: %v", role.Organization, policy.SubjectORegexes)
		}

		if !checkStringArrByRegexp(role.OU, policy.SubjectOURegexes, false) {
			return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", role.OU, policy.SubjectOURegexes)
		}

		if !checkStringArrByRegexp(role.Country, policy.SubjectCRegexes, false) {
			return fmt.Errorf("country %v doesn't match regexps: %v", role.Country, policy.SubjectCRegexes)
		}

		if !checkStringArrByRegexp(role.Locality, policy.SubjectLRegexes, false) {
			return fmt.Errorf("city (locality) %v doesn't match regexps: %v", role.Locality, policy.SubjectLRegexes)
		}

		if !checkStringArrByRegexp(role.Province, policy.SubjectSTRegexes, false) {
			return fmt.Errorf("state (province) %v doesn't match regexps: %v", role.Province, policy.SubjectSTRegexes)
		}
		if !checkKey(role.KeyType, role.KeyBits, ecdsaCurvesSizesToName(role.KeyBits), policy.AllowedKeyConfigurations) {
			return fmt.Errorf("key type is not allowed by Venafi policies")
		}

	}

	//TODO: check against upn_san_regexes

	extKeyUsage, err := parseExtKeyUsageParameter(role.ExtKeyUsage)
	if err != nil {
		return err
	}
	if !isCA {
		if !compareEkuList(extKeyUsage, policyConfig.ExtKeyUsage) {
			return fmt.Errorf("different EKU in Venafi policy config and role")
		}
	}

	return nil
}

func checkCSR(isCA bool, csr *x509.CertificateRequest, policy venafiPolicyEntry) error {
	if isCA {
		if len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || (len(csr.DNSNames) != 0 &&
			csr.DNSNames[0] != csr.Subject.CommonName) { //workaround for setting SAN if CA have normal domain in CN
			return fmt.Errorf("CA doesn't allow any SANs: %v, %v, %v, %v", csr.EmailAddresses, csr.DNSNames, csr.IPAddresses, csr.URIs)
		}
	} else {
		if !checkStringByRegexp(csr.Subject.CommonName, policy.SubjectCNRegexes) {
			return fmt.Errorf("common name %s doesn't match regexps: %v", csr.Subject.CommonName, policy.SubjectCNRegexes)
		}
		if !checkStringArrByRegexp(csr.EmailAddresses, policy.EmailSanRegExs, true) {
			return fmt.Errorf("email SANs %v do not match regexps: %v", csr.EmailAddresses, policy.EmailSanRegExs)
		}
		if !checkStringArrByRegexp(csr.DNSNames, policy.DnsSanRegExs, true) {
			return fmt.Errorf("DNS SANs %v do not match regexps: %v", csr.DNSNames, policy.DnsSanRegExs)
		}
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		if !checkStringArrByRegexp(ips, policy.IpSanRegExs, true) {
			return fmt.Errorf("IP SANs %v do not match regexps: %v", ips, policy.IpSanRegExs)
		}
		uris := make([]string, len(csr.URIs))
		for i, uri := range csr.URIs {
			uris[i] = uri.String()
		}
		if !checkStringArrByRegexp(uris, policy.UriSanRegExs, true) {
			return fmt.Errorf("URI SANs %v do not match regexps: %v", uris, policy.UriSanRegExs)
		}
	}
	if !checkStringArrByRegexp(csr.Subject.Organization, policy.SubjectORegexes, false) {
		return fmt.Errorf("organization %v doesn't match regexps: %v", csr.Subject.Organization, policy.SubjectORegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.OrganizationalUnit, policy.SubjectOURegexes, false) {
		return fmt.Errorf("organizational unit (ou) %v doesn't match regexps: %v", csr.Subject.OrganizationalUnit, policy.SubjectOURegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.Country, policy.SubjectCRegexes, false) {
		return fmt.Errorf("country %v doesn't match regexps: %v", csr.Subject.Country, policy.SubjectCRegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.Locality, policy.SubjectLRegexes, false) {
		return fmt.Errorf("city (locality) %v doesn't match regexps: %v", csr.Subject.Locality, policy.SubjectLRegexes)
	}

	if !checkStringArrByRegexp(csr.Subject.Province, policy.SubjectSTRegexes, false) {
		return fmt.Errorf("state (province) %v doesn't match regexps: %v", csr.Subject.Province, policy.SubjectSTRegexes)
	}
	keyValid := true
	if csr.PublicKeyAlgorithm == x509.RSA {
		pubkey, ok := csr.PublicKey.(*rsa.PublicKey)
		if ok {
			keyValid = checkKey("rsa", pubkey.Size()*8, "", policy.AllowedKeyConfigurations)
		} else {
			log.Printf("%s invalid key in CSR", logPrefixVenafiPolicyEnforcement)
		}
	} else if csr.PublicKeyAlgorithm == x509.ECDSA {
		pubkey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if ok {
			keyValid = checkKey("ecdsa", 0, pubkey.Curve.Params().Name, policy.AllowedKeyConfigurations)
		}
	}
		if !keyValid {
			return fmt.Errorf("key type is not allowed by Venafi policies")
		}
		return nil
	}

func (b *backend) getVenafiPolicyConfig(ctx context.Context, s *logical.Storage, n string) (*venafiPolicyConfigEntry, error) {
	entry, err := (*s).Get(ctx, venafiPolicyPath+n)
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
	ExtKeyUsage            []x509.ExtKeyUsage `json:"ext_key_usage"`
	AutoRefreshInterval    int64              `json:"auto_refresh_interval"`
	LastPolicyUpdateTime   int64              `json:"last_policy_update_time"`
	VenafiImportTimeout    int                `json:"import_timeout"`
	VenafiImportWorkers    int                `json:"import_workers"`
	CreateRole             bool               `json:"create_role"`
	VenafiSecret           string             `json:"venafi_secret"`
	Zone                   string             `json:"zone"`
	ImportOnlyNonCompliant bool               `json:"import_only_non_compliant"`
}

type venafiPolicyEntry struct {
	SubjectCNRegexes         []string                           `json:"subject_cn_regexes"`
	SubjectORegexes          []string                           `json:"subject_o_regexes"`
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
