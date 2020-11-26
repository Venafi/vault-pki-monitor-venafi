package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	venafiSecretPath                 = "venafi/"
	venafiSecretDefaultName          = "secret_"
	pathVenafiSecretsSynopsis        = "Manage the Venafi secrets that can be created with this backend."
	pathVenafiSecretsDescription     = "This path lets you manage the Venafi secrets that can be created with this backend." // #nosec G101
	pathVenafiSecretsListSynopsis    = "List the existing Venafi secrets in this backend."
	pathVenafiSecretsListDescription = "Venafi secrets will be listed by the secret name." // #nosec G101
	tokenMode                        = `TPP Token (access_token, refresh_token)` // #nosec G101
	tppMode                          = `TPP Credentials (tpp_user, tpp_password)`
	cloudMode                        = `Cloud API Key (apikey)`
	errorMultiModeMessage            = `can't specify both: %s and %s modes in the same venafi secret`
	errorTextURLEmpty                = `"url" argument is required`
	errorTextZoneEmpty               = `"zone" argument is required`
	errorTextInvalidMode             = "invalid mode: apikey or tpp credentials or tpp access/refresh token required"
)

var (
	errorTextMixedTPPAndCloud   = fmt.Sprintf(errorMultiModeMessage, tppMode, cloudMode)
	errorTextMixedTokenAndCloud = fmt.Sprintf(errorMultiModeMessage, tokenMode, cloudMode)
)

func pathVenafiSecretsList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiSecretPath + "?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListVenafiSecrets,
				Summary:  "Return all venafi secrets.",
			},
		},
		HelpSynopsis:    pathVenafiSecretsListSynopsis,
		HelpDescription: pathVenafiSecretsListDescription,
	}

	return ret
}

func pathVenafiSecrets(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: venafiSecretPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the Venafi secret.",
			},
			"tpp_url": {
				Type:        framework.TypeString,
				Description: `URL of Venafi Platform. Deprecated, use 'url' instead`,
				Deprecated:  true,
			},
			"url": {
				Type:        framework.TypeString,
				Description: `URL of Venafi API endpoint. Example: https://tpp.venafi.example/vedsdk`,
				Required:    true,
			},
			"access_token": {
				Type:        framework.TypeString,
				Description: `Access token for TPP, user should use this for authentication`,
				Required:    true,
			},
			"refresh_token": {
				Type:        framework.TypeString,
				Description: `Refresh token for obtaining a new access token for TPP`,
				Required:    true,
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
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"apikey": {
				Type:        framework.TypeString,
				Description: `API key for Venafi Cloud. Example: 142231b7-cvb0-412e-886b-6a1ght0bc93d`,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"cloud_url": {
				Type:        framework.TypeString,
				Description: `URL for Venafi Cloud. Set it only if you want to use non production Cloud. Deprecated, use 'url' instead`,
				Deprecated:  true,
			},
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platform or Cloud policy. 
Example for Platform: testPolicy\\vault
Example for Venafi Cloud: Default`,
				Default:  `Default`,
				Required: true,
			},
			"trust_bundle_file": {
				Type: framework.TypeString,
				Description: `Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.
Example:
  trust_bundle_file = "/full/path/to/chain.pem""`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadVenafiSecret,
				Summary:  "Return the venafi resource specified in path.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpdateVenafiSecret,
				Summary:  "Configure a Venafi resource for use with the Venafi Policy.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathDeleteVenafiSecret,
				Summary:  "Removes the Venafi resource specified in path.",
			},
		},
		HelpSynopsis:    pathVenafiSecretsSynopsis,
		HelpDescription: pathVenafiSecretsDescription,
	}

	return ret
}

func (b *backend) pathListVenafiSecrets(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, venafiSecretPath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathReadVenafiSecret(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretName := data.Get("name").(string)
	if len(secretName) == 0 {
		return logical.ErrorResponse("missing venafi secret name"), nil
	}

	cred, err := b.getVenafiSecret(ctx, &req.Storage, secretName)
	if err != nil {
		return nil, err
	}

	if cred == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: cred.ToResponseData(),
	}

	return resp, nil
}

func (b *backend) getVenafiSecret(ctx context.Context, s *logical.Storage, name string) (*venafiSecretEntry, error) {
	entry, err := (*s).Get(ctx, venafiSecretPath+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var result venafiSecretEntry
	err = entry.DecodeJSON(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathUpdateVenafiSecret(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)

	url := data.Get("url").(string)
	tppUrl := data.Get("tpp_url").(string)
	cloudUrl := data.Get("cloud_url").(string)

	if url == "" {

		if tppUrl != "" {
			url = tppUrl
		} else if cloudUrl != "" {
			url = cloudUrl
		}
	}

	entry := &venafiSecretEntry{
		URL:             url,
		Zone:            data.Get("zone").(string),
		TPPUrl:          tppUrl,
		TPPUser:         data.Get("tpp_user").(string),
		TPPPassword:     data.Get("tpp_password").(string),
		AccessToken:     data.Get("access_token").(string),
		RefreshToken:    data.Get("refresh_token").(string),
		CloudURL:        cloudUrl,
		Apikey:          data.Get("apikey").(string),
		TrustBundleFile: data.Get("trust_bundle_file").(string),
	}

	err = validateVenafiSecretEntry(entry)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if entry.RefreshToken != "" {

		cfg, err := createConfigFromFieldData(entry)

		if err != nil {

			return logical.ErrorResponse(err.Error()), nil

		}

		tokenInfo, err := getAccessData(cfg)

		if err != nil {

			return logical.ErrorResponse(err.Error()), nil

		} else {

			if tokenInfo.Access_token != "" {
				entry.AccessToken = tokenInfo.Access_token
			}

			if tokenInfo.Refresh_token != "" {
				entry.RefreshToken = tokenInfo.Refresh_token
			}

		}

	}

	jsonEntry, err := logical.StorageEntryJSON(venafiSecretPath+name, entry)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, jsonEntry)
	if err != nil {
		return nil, err
	}

	var logResp *logical.Response

	warnings := getWarnings(entry, name)

	if cap(warnings) > 0 {
		logResp = &logical.Response{

			Data:     map[string]interface{}{},
			Redirect: "",
			Warnings: warnings,
		}
		return logResp, nil
	}

	return nil, nil
}

func (b *backend) pathDeleteVenafiSecret(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	//Deleting secrets path
	err := req.Storage.Delete(ctx, venafiSecretPath+name)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (c *venafiSecretEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"url":               c.URL,
		"zone":              c.Zone,
		"tpp_user":          c.TPPUser,
		"tpp_password":      c.getMaskString(),
		"access_token":      c.getMaskString(),
		"refresh_token":     c.getMaskString(),
		"apikey":            c.getMaskString(),
		"trust_bundle_file": c.TrustBundleFile,
	}
	return responseData
}

func getWarnings(c *venafiSecretEntry, name string) []string {

	var warnings []string

	if c.TPPUrl != "" {
		warnings = append(warnings, "tpp_url is deprecated, please use url instead")
	}

	if c.CloudURL != "" {
		warnings = append(warnings, "cloud_url is deprecated, please use url instead")
	}

	if c.TPPUser != "" {
		warnings = append(warnings, "tpp_user is deprecated, please use access_token instead")
	}

	if c.TPPPassword != "" {
		warnings = append(warnings, "tpp_password is deprecated, please use access_token instead")
	}

	//Include success message in warnings
	if len(warnings) > 0 {
		warnings = append(warnings, "Venafi secret: "+name+" saved successfully")
	}

	return warnings
}

func validateVenafiSecretEntry(entry *venafiSecretEntry) error {
	if entry.Apikey == "" && (entry.TPPUser == "" || entry.TPPPassword == "") && entry.AccessToken == "" && entry.RefreshToken == "" {
		return fmt.Errorf(errorTextInvalidMode)
	}

	//When api key is null, that means TPP is being used, and requires a URL
	if entry.URL == "" && entry.Apikey == "" {
		return fmt.Errorf(errorTextURLEmpty)
	}

	if entry.Zone == "" {
		return fmt.Errorf(errorTextZoneEmpty)
	}

	if entry.TPPUser != "" && entry.Apikey != "" {
		return fmt.Errorf(errorTextMixedTPPAndCloud)
	}

	if entry.AccessToken != "" && entry.Apikey != "" {
		return fmt.Errorf(errorTextMixedTokenAndCloud)
	}

	return nil
}
