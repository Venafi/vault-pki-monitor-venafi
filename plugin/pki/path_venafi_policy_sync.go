package pki

import (
	"context"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/framework"
	hconsts "github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"regexp"
	"strings"
	"time"
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

		policyMap, err := getPolicyRoleMap(ctx, req.Storage)
		if err != nil {
			return
		}

		//Get Venafi policy in entry format
		if policyMap.Roles[roleName].DefaultsPolicy == "" {
			continue
		}

		var entry []string
		entry = append(entry, fmt.Sprintf("role: %s sync policy: %s", roleName, policyMap.Roles[roleName].DefaultsPolicy))
		entries = append(entries, entry...)

	}
	return logical.ListResponse(entries), nil
}

func (b *backend) syncRoleWithVenafiPolicyRegister(conf *logical.BackendConfig) {
	log.Printf("%s registering policy sync controller", logPrefixVenafiPolicyEnforcement)
	b.taskStorage.register("policy-sync-controller", func() {
		err := b.syncPolicyEnforcementAndRoleDefaults(conf)
		if err != nil {
			log.Printf("%s %s", logPrefixVenafiPolicyEnforcement, err)
		}
	}, 1, time.Second*15)
}

func (b *backend) syncPolicyEnforcementAndRoleDefaults(conf *logical.BackendConfig) (err error) {
	replicationState := conf.System.ReplicationState()
	//Checking if we are on master or on the stanby Vault server
	isSlave := !(conf.System.LocalMount() || !replicationState.HasState(hconsts.ReplicationPerformanceSecondary)) ||
		replicationState.HasState(hconsts.ReplicationDRSecondary) ||
		replicationState.HasState(hconsts.ReplicationPerformanceStandby)
	if isSlave {
		log.Printf("%s We're on slave. Sleeping", logPrefixVenafiPolicyEnforcement)
		return
	}
	log.Printf("%s We're on master. Starting to synchronise policy", logPrefixVenafiPolicyEnforcement)

	ctx := context.Background()
	//Get policy list for enforcement sync
	policiesRaw, err := b.storage.List(ctx, venafiPolicyPath)
	if err != nil {
		return err
	}
	var policies []string

	//Removing from policy list repeated policy name with / at the end
	for _, p := range policiesRaw {
		if !strings.Contains(p, "/") {
			policies = append(policies, p)
		}
	}

	for _, policyName := range policies {

		policyConfig, err := b.getVenafiPolicyConfig(ctx, &b.storage, policyName)
		if err != nil {
			log.Printf("%s Error getting policy config for policy %s: %s", logPrefixVenafiPolicyEnforcement, policyName, err)
			continue
		}

		if policyConfig == nil {
			log.Printf("%s Policy config for %s is nil. Skipping", logPrefixVenafiPolicyEnforcement, policyName)
			continue
		}

		log.Printf("%s check last policy updated time", logPrefixVenafiPolicyEnforcement)
		timePassed := time.Now().Unix() - policyConfig.LastPolicyUpdateTime

		//update only if needed
		//TODO: Make test to check this refresh
		if (timePassed) < policyConfig.AutoRefreshInterval {
			continue
		}

		//Refresh Venafi policy regexes
		err = b.refreshVenafiPolicyEnforcementContent(b.storage, policyName)
		if err != nil {
			log.Printf("%s Error  refreshing venafi policy content: %s", logPrefixVenafiPolicyEnforcement, err)
			continue
		}
		//Refresh roles defaults
		//Get role list with role sync param
		rolesList, err := b.getRolesListForVenafiPolicy(ctx, b.storage, policyName)
		if err != nil {
			continue
		}

		if len(rolesList.defaultsRoles) == 0 {
			log.Printf("%s No roles found for refreshing defaults in policy %s", logPrefixVenafiRoleyDefaults, policyName)
			continue
		}

		for _, roleName := range rolesList.defaultsRoles {
			log.Printf("Synchronizing role %s", roleName)
			msg := b.synchronizeRoleDefaults(ctx, b.storage, roleName, policyName)
			log.Printf("%s %s", logPrefixVenafiRoleyDefaults, msg)
		}

		//policy config's credentials may be got updated so get it from storage again before saving it.
		policyConfig, _ = b.getVenafiPolicyConfig(ctx, &b.storage, policyName)

		//set new last updated
		policyConfig.LastPolicyUpdateTime = time.Now().Unix()

		//put new policy entry with updated time value
		jsonEntry, err := logical.StorageEntryJSON(venafiPolicyPath+policyName, policyConfig)
		if err != nil {
			return fmt.Errorf("Error converting policy config into JSON: %s", err)

		}
		if err := b.storage.Put(ctx, jsonEntry); err != nil {
			return fmt.Errorf("Error saving policy last update time: %s", err)

		}
	}

	return err
}

func (b *backend) synchronizeRoleDefaults(ctx context.Context, storage logical.Storage, roleName string, policyName string) (msg string) {
	//	Read previous role parameters
	pkiRoleEntry, err := b.getPKIRoleEntry(ctx, storage, roleName)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	if pkiRoleEntry == nil {
		return fmt.Sprintf("PKI role %s is empty or does not exist", roleName)
	}

	//Get Venafi policy in entry format
	policyMap, err := getPolicyRoleMap(ctx, storage)
	if err != nil {
		return
	}
	if policyMap.Roles[roleName].DefaultsPolicy == "" {
		return fmt.Sprintf("role %s do not have venafi_defaults_policy attribute", roleName)
	}

	entry, err := storage.Get(ctx, venafiPolicyPath+policyName)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	if entry == nil {
		return "entry is nil"
	}

	var policy venafiPolicyConfigEntry
	err = entry.DecodeJSON(&policy)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	secret, err := b.getVenafiSecret(ctx, &storage, policy.VenafiSecret)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	zone := policy.Zone
	if zone == "" {
		zone = secret.Zone
	}

	venafiPolicyEntry, err := b.getVenafiPolicyParams(ctx, storage, policyName, zone)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	//  Replace PKI entry with Venafi policy values
	replacePKIValue(&pkiRoleEntry.OU, venafiPolicyEntry.OU)
	replacePKIValue(&pkiRoleEntry.Organization, venafiPolicyEntry.Organization)
	replacePKIValue(&pkiRoleEntry.Country, venafiPolicyEntry.Country)
	replacePKIValue(&pkiRoleEntry.Locality, venafiPolicyEntry.Locality)
	replacePKIValue(&pkiRoleEntry.Province, venafiPolicyEntry.Province)
	replacePKIValue(&pkiRoleEntry.StreetAddress, venafiPolicyEntry.StreetAddress)
	replacePKIValue(&pkiRoleEntry.PostalCode, venafiPolicyEntry.PostalCode)

	//does not have to configure the role to limit domains
	// because the Venafi policy already constrains that area
	pkiRoleEntry.AllowAnyName = true
	pkiRoleEntry.AllowedDomains = []string{}
	pkiRoleEntry.AllowSubdomains = true
	//TODO: we need to sync key settings as well. But before it we need to add key type to zone configuration
	//in vcert SDK

	// Put new entry
	jsonEntry, err := logical.StorageEntryJSON("role/"+roleName, pkiRoleEntry)
	if err != nil {
		return fmt.Sprintf("Error creating json entry for storage: %s", err)
	}
	if err := storage.Put(ctx, jsonEntry); err != nil {
		return fmt.Sprintf("Error putting entry to storage: %s", err)
	}

	return fmt.Sprintf("finished synchronizing role %s", roleName)
}

func replacePKIValue(original *[]string, zone []string) {
	if len(zone) > 0 {
		if zone[0] != "" {
			*original = zone
		}

	}
}

func (b *backend) getVenafiPolicyParams(ctx context.Context, storage logical.Storage, policyConfig string, syncZone string) (entry roleEntry, err error) {
	//Get role params from TPP\Cloud
	cl, err := b.ClientVenafi(ctx, &storage, policyConfig)
	if err != nil {
		return entry, fmt.Errorf("could not create venafi client: %s", err)
	}

	cl.SetZone(syncZone)
	zone, err := cl.ReadZoneConfiguration()
	if (err != nil) && (cl.GetType() == endpoint.ConnectorTypeTPP) {
		msg := err.Error()

		//catch the scenario when token is expired and deleted.
		var regex = regexp.MustCompile("(expired|invalid)_token")

		//validate if the error is related to a expired accces token, at this moment the only way can validate this is using the error message
		//and verify if that message describes errors related to expired access token.
		code := getStatusCode(msg)
		if code == HTTP_UNAUTHORIZED && regex.MatchString(msg){
			cfg, err := b.getConfig(ctx, &storage, policyConfig)

			if err != nil {
				return entry, err
			}

			if cfg.Credentials.RefreshToken != "" {
				err = synchronizedUpdateAccessToken(cfg, b, ctx, &storage, policyConfig)

				if err != nil {
					return entry, err
				}

				//everything went fine so get the new client with the new refreshed access token
				cl, err := b.ClientVenafi(ctx, &storage, policyConfig)
				if err != nil {
					return entry, err
				}

				b.Logger().Debug("Reading policy configuration again")

				zone, err = cl.ReadZoneConfiguration()
				if err != nil {
					return entry, err
				} else {
					entry = roleEntry{
						OU:           zone.OrganizationalUnit,
						Organization: []string{zone.Organization},
						Country:      []string{zone.Country},
						Locality:     []string{zone.Locality},
						Province:     []string{zone.Province},
					}
					return entry, nil
				}
			} else {
				err = fmt.Errorf("Tried to get new access token but refresh token is empty")
				return entry, err
			}

		} else {
			return entry, err
		}
	}
	if err != nil {
		return entry, fmt.Errorf("could not read zone configuration: %s", err)
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
