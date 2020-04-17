package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	hconsts "github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
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

		//Get Venafi policy in entry format
		if pkiRoleEntry.VenafiDefaultsPolicy == "" {
			continue
		}

		var entry []string
		entry = append(entry, fmt.Sprintf("role: %s sync policy: %s", roleName, pkiRoleEntry.VenafiDefaultsPolicy))
		entries = append(entries, entry...)

	}
	return logical.ListResponse(entries), nil
}

func (b *backend) syncRoleWithVenafiPolicyRegister(storage logical.Storage, conf *logical.BackendConfig) {
	log.Println("registering policy sync controller")
	b.taskStorage.register("policy-sync-controller", func() {
		err := b.syncRoleWithVenafiPolicy(storage, conf)
		if err != nil {
			log.Printf("%s", err)
		}
	}, 1, time.Second*15)
}

func (b *backend) syncRoleWithVenafiPolicy(storage logical.Storage, conf *logical.BackendConfig) (err error) {
	replicationState := conf.System.ReplicationState()
	//Checking if we are on master or on the stanby Vault server
	isSlave := !(conf.System.LocalMount() || !replicationState.HasState(hconsts.ReplicationPerformanceSecondary)) ||
		replicationState.HasState(hconsts.ReplicationDRSecondary) ||
		replicationState.HasState(hconsts.ReplicationPerformanceStandby)
	if isSlave {
		log.Println("We're on slave. Sleeping")
		return
	}
	log.Println("We're on master. Starting to synchronise policy")

	ctx := context.Background()
	//Get policy list for enforcement sync
	policiesRaw, err := storage.List(ctx, venafiPolicyPath)
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

		policyConfig, err := b.getVenafiPolicyConfig(ctx, storage, policyName)
		if err != nil {
			log.Printf("Error getting policy config for policy %s: %s", policyName, err)
			continue
		}

		if policyConfig == nil {
			log.Printf("Policy config for %s is nil. Skipping", policyName)
			continue
		}

		log.Println("check last policy updated time")
		timePassed := time.Now().Unix() - policyConfig.LastPolicyUpdateTime

		//update only if needed
		if (timePassed) < policyConfig.AutoRefreshInterval {
			continue
		}

		//Refresh Venafi policy regexes
		err = b.refreshVenafiPolicyContent(storage, policyName)
		if err != nil {
			log.Printf("Error  refreshing venafi policy content: %s", err)
			continue
		}
		//Refresh roles defaults
		//Get role list with role sync param
		rolesList, err := b.getRolesListForVenafiPolicy(ctx, storage, policyName)
		if err != nil {
			continue
		}

		if len(rolesList.defaultsRoles) == 0 {
			log.Printf("No roles found for refreshing defaults in policy %s", policyName)
			continue
		}

		for _, roleName := range rolesList.defaultsRoles {
			//	Read previous role parameters
			pkiRoleEntry, err := b.getPKIRoleEntry(ctx, storage, roleName)
			if err != nil {
				log.Printf("%s", err)
				continue
			}

			if pkiRoleEntry == nil {
				log.Printf("PKI role %s is empty or does not exist", roleName)
				continue
			}

			//Get Venafi policy in entry format
			if pkiRoleEntry.VenafiDefaultsPolicy == "" {
				continue
			}

			entry, err := storage.Get(ctx, venafiPolicyPath+policyName)
			if err != nil {
				log.Println(err)
				continue
			}

			if entry == nil {
				log.Println("entry is nil")
				continue
			}

			var venafiConfig venafiConnectionConfig
			if err := entry.DecodeJSON(&venafiConfig); err != nil {
				log.Printf("error reading Venafi policy configuration: %s", err)
				continue
			}

			venafiPolicyEntry, err := b.getVenafiPolicyParams(ctx, storage, policyName,
				venafiConfig.Zone)
			if err != nil {
				log.Printf("%s", err)
				continue
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
				log.Printf("Error creating json entry for storage: %s", err)
				continue
			}
			if err := storage.Put(ctx, jsonEntry); err != nil {
				log.Printf("Error putting entry to storage: %s", err)
				continue
			}
		}

		//set new last updated
		policyConfig.LastPolicyUpdateTime = time.Now().Unix()

		//put new policy entry with updated time value
		jsonEntry, err := logical.StorageEntryJSON(venafiPolicyPath+policyName, policyConfig)
		if err != nil {
			return fmt.Errorf("Error converting policy config into JSON: %s", err)

		}
		if err := storage.Put(ctx, jsonEntry); err != nil {
			return fmt.Errorf("Error saving policy last update time: %s", err)

		}
	}

	return err
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
	cl, err := b.ClientVenafi(ctx, storage, policyConfig)
	if err != nil {
		return entry, fmt.Errorf("could not create venafi client: %s", err)
	}

	cl.SetZone(syncZone)
	zone, err := cl.ReadZoneConfiguration()
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
