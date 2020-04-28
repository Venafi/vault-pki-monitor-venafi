![Venafi](Venafi_logo.png)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 18.2+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2018.2+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# Venafi PKI Monitoring Secrets Engine for HashiCorp Vault

This solution allows [HashiCorp Vault](https://www.vaultproject.io/) users to provide their
Information Security organization visibility into certificate issuance.
Vault issued certificates are automatically forwarded to the 
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or the [Venafi Cloud for DevOps](https://www.venafi.com/platform/cloud/devops) service which enables
risk assessment, incident response, and auditing that ensures compliance with enterprise security policy.
The [secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html) component was sourced from the
original HashiCorp Vault PKI secrets engine.

## Dependencies

* HashiCorp Vault: https://www.vaultproject.io/downloads.html

## Requirements for use with Trust Protection Platform

1. For policy enforcement, the Venafi WebSDK user that Vault will be using needs to have been granted view and read
   permissions to the policy folder from which Venafi policy will be obtained.
1. For issuance visibility, the Venafi WebSDK user that Vault will be using needs to have been granted write and create
   permission to the policy folder where Vault issued certificates will be imported, and the 
   _Allow Users to Import Duplicate Certificates and Reuse Private Keys_ policy of that folder needs to be set to 'Yes'
   to ensure that all certificates issued by the Vault can be imported.

### Establishing Trust between Vault and Trust Protection Platform

It is not common for the Venafi Platform's REST API (WebSDK) to be secured using a certificate
issued by a publicly trusted CA, therefore establishing trust for that server certificate is a
critical part of your configuration. Ideally this is done by obtaining the root CA certificate in
the issuing chain in PEM format and copying that file to your Vault server
(e.g. /opt/venafi/bundle.pem).  You then reference that file using the 'trust_bundle_file'
parameter whenever you create a new PKI role in your Vault.

## Quickstart: Enabling the Plug-in

This solution is a [plugin](https://www.vaultproject.io/docs/internals/plugins.html)
for HashiCorp Vault. This guide assumes you have already installed Vault and have a basic
understanding of how it works. If that's not the case, please read the
[getting started](https://www.vaultproject.io/intro/getting-started/install.html) guide
for Vault.

This plugin was originally sourced from the
[built-in Vault PKI secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html)
and enhanced with features for integrating with Venafi Platform and Cloud.

1. Review the notes for [latest release](https://github.com/Venafi/vault-pki-monitor-venafi/releases/latest)
and identify the `vault-pki-monitor-venafi` zip package that applies to your operating system and
use case. There are two versions, optional and strict. The "optional" version allows certificates
to be issued by the Vault CA when there is no Venafi policy applied whereas the "strict" version
will return the following error when there is no Venafi policy applied: *policy data is nil. You
need to configure Venafi policy to proceed*
   
1. Download the `vault-pki-monitor-venafi` zip package, then calculate the SHA256 hashsum and
compare the value to the one listed in the release notes to ensure they match.  File names change
with each release so the following commands may not represent the latest version.
   ```
   $ wget -q https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/v0.6.0/vault-pki-monitor-venafi_v0.6.0+496_linux_st
   rict.zip
   $ sha256sum vault-pki-monitor-venafi_v0.6.0+496_linux_strict.zip
   48f9d916698fada0370be65b193dece5f6a395ef17be5be189dc047b4a54c612  vault-pki-monitor-venafi_v0.6.0+496_linux_strict.zip
   ```

1. Unzip the plugin binary and move it to the `/etc/vault/vault_plugins` directory (or a custom
directory of your choosing):
   ```
   $ unzip vault-pki-monitor-venafi_v0.6.0+496_linux_strict.zip
   Archive:  vault-pki-monitor-venafi_v0.6.0+496_linux_strict.zip
     inflating: vault-pki-monitor-venafi_strict
   $ mv vault-pki-monitor-venafi_strict /etc/vault/vault_plugins
   ```
    
1. Configure the plugin directory for your Vault by specifying it in the server configuration file:
   ```
   $ echo 'plugin_directory = "/etc/vault/vault_plugins"' > vault-config.hcl
   ```

1. Start your Vault server (note: if you don't have working configuration you can start it in dev mode.):  
   **Dev mode is only for educational or development purposes. Don't use it in production!**
   ```
   $ vault server -log-level=debug -dev -config=vault-config.hcl
   ```

1. Export the VAULT_ADDR environment variable so that the Vault client will interact with the local Vault:
   ```
   $ export VAULT_ADDR=http://127.0.0.1:8200
   ```

1. Calculate the SHA-256 checksum of `vault-pki-monitor-venafi` plugin binary:
   ```
   $ SHA256=$(sha256sum /etc/vault/vault_plugins/vault-pki-monitor-venafi_strict |cut -d' ' -f1)
   $ echo $SHA256
   add88792d6b541f30ec8e7b015a157379a25263e1017dc283b1f3dc2e7c8944f
   ```

1. Register the `vault-pki-monitor-venafi` plugin in the Vault system catalog:
   ```
   $ vault write sys/plugins/catalog/secret/vault-pki-monitor-venafi_strict \
       sha_256="${SHA256}" command="vault-pki-monitor-venafi_strict"
   Success! Data written to: sys/plugins/catalog/secret/vault-pki-monitor-venafi_strict
   ```

1. Enable the secrets engine for the `vault-pki-monitor-venafi` plugin:
   ```
   $ vault secrets enable -path=pki -plugin-name=vault-pki-monitor-venafi_strict plugin
   Success! Enabled the vault-pki-monitor-venafi_strict secrets engine at: pki/
   ```

[![asciicast](https://asciinema.org/a/vmo1iE4fj3bDQFOByCSVH5h4D.svg)](https://asciinema.org/a/vmo1iE4fj3bDQFOByCSVH5h4D)

## Quickstart: Enabling Venafi Policy Enforcement

Venafi Policy limits the PKI role based on Venafi Platform policies or Venafi Cloud zones.  Policy enforcement is
configured using the special *venafi-policy* path which InfoSec teams can use to require compliance from a Vault CA.

1. Write default Venafi policy configuration into *venafi-policy* path:
    1. Make credentials variable for Trust Protection Platform:
    ```
    export CREDS='tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone=DevOps\\Default \
        trust_bundle_file=/opt/venafi/bundle.pem'
    ```
    1. Or for the Cloud:
    ```
    export CREDS='api_key="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"'
    ```
   
    1. Write the configuration into vault
    ```
    vault write pki/venafi-policy/default $CREDS
    ```
    Following options are supported (note: this list can also be viewed from the command line using `vault path-help pki/venafi-policy/default`):  
    
    | Parameter           | Type    | Description                                                                   | Example   |
    | ------------------- | ------- | ------------------------------------------------------------------------------| --------- |
    |`api_key`               |string   | API key for Venafi Cloud.                                                   |`142231b7-cvb0-412e-886b-6aeght0bc93d`|
    |`ext_key_usage`        |string   | A comma-separated string or list of allowed extended key usages.            |`ServerAuth,ClientAuth`|
    |`name`                 |string   | Name of the Venafi policy config. IS not set will be `default`              |`another-policy`|
    |`tpp_password`         |string   | Password for web API user                                                   |`password`|
    |`tpp_url`              |string   | URL of Venafi Platform.                                                     |`https://tpp.venafi.example/vedsdk`|
    |`tpp_user`             |string   | Web API user for Venafi Platform                                            |`admin`|
    |`trust_bundle_file`    |string   | Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.|`"/full/path/to/chain.pem"`|
    |`zone`                 |string   | Name of Venafi Platform policy or Venafi Cloud Zone ID.                     |`testpolicy\\vault`|
    |`auto_refresh_interval`| int | Interval of policy update from Venafi in seconds. Set it to 0 to disable automatic policy| 0|    
    | `import_timeout` | int     | Maximum wait in seconds before re-attempting certificate import from queue    | 15        |
    | `import_workers` | int     | Maximum number of concurrent threads to use for VCert import                  | 12        |
    |`enforcement_roles`   |string   | List of roles where policy enfrcement is enabled                            |`tpp`|
    |`defaults_roles`      |string   | List of roles where default values from Venafi will be set                            |`tpp`|
    |`import_roles`               |string   | List of roles from where certificates will be imported to Venafi                          |`tpp`|        
    |

    Policy will be downloaded from Venafi, parsed, saved under the specified path, and displayed to the user. After policy
    creation, any requested certificate will be checked against it.  If the request fails compliance with the policy, the
    user will see error similar to that of standard PKI role checking except stating "not allowed by Venafi policy":

    ```
    URL: PUT http://127.0.0.1:8200/v1/vault-pki-monitor-venafi/issue/domain.com
    Code: 400. Errors:

    * common name import-vl9kt.import.example.com not allowed by Venafi policy
    ```

1. Create a role with which you want to use enforcement policy
    ```
    vault write pki/roles/test-role \
        generate_lease=true ttl=1h max_ttl=1h \
        allow_any_name=true
    ``` 
   
1. Update the policy and add created role to the defaults and enforcement lists
   ```
   vault write pki/venafi-policy/default $CREDS defaults_roles="test-role" enforcement_roles="test-role"
   ```

1. The following command can be used to display the current Venafi policy:
    ```
    vault read pki/venafi-policy/default/policy
    ```
    
1. The Venafi configuration for the policy can be viewed using the following:
    ```
    vault read pki/venafi-policy/default
    ``` 

1. You can also use multiple Venafi policies by simply applying them to different roles.
    1. Write another policy configuration:
    ```
    vault write pki/venafi-policy/another-policy \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Another policy" \
        trust_bundle_file="/opt/venafi/bundle.pem" \
        defaults_roles="venafi-role2" \
        enforcement_roles="venafi-role2"
    ```

1. Venafi policy can be cleared using `delete` operation on the *venafi-policy* path (useful if you want to see the
   behavior when no Venafi policy is applied):
    ```
    vault delete pki/venafi-policy
    ```
    
### Testing Policy Enforcement

1. Initialize the Vault PKI certificate authority:
    ```
    vault write pki/root/generate/internal common_name="Vault Test Root CA" ttl=8760h
    ```

1. Create a very permissive role because Venafi policy enforcement will prevent the Vault CA from issuing certificates that
   do not comply with enterprise security policy:
    ```
    vault write pki/roles/test-role \
        generate_lease=true ttl=1h max_ttl=1h \
        allow_any_name=true
    ```

1. Enroll a certificate using the CA and specify a domain that will fail policy:
    ```
    vault write pki/issue/test-role common_name="test.forbidden.org" alt_names="test-1.forbidden.org,test-2.forbidden.org"
    ```
    
1. Try again but specify a domain that will comply with policy:
    ```
    vault write pki/issue/test-role common_name="test.allowed.org" alt_names="test-1.allowed.org,test-2.allowed.org"
    ```
    
[![asciicast](https://asciinema.org/a/exZfzOOFyuxjvvQ61RE74B1LC.svg)](https://asciinema.org/a/exZfzOOFyuxjvvQ61RE74B1LC)    
    
## Quickstart: Enabling Venafi Visibility

# !! Need to rewrite this section. Visibility is on on the policy level now
1. Visibiliy is enabled at the [PKI role](https://www.vaultproject.io/docs/secrets/pki/index.html) by enabling the `venafi_import` option:
    1. For the Venafi Platform:
    ```
    vault write pki/roles/venafi-role \
        venafi_import=true \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Vault Monitor" \
        trust_bundle_file="/opt/venafi/bundle.pem" \
        generate_lease=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```
    2. For Venafi Cloud:
    ```
    vault write pki/roles/venafi-role \
        venafi_import=true \
        apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
        zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz" \
        generate_lease=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```

The following options are supported (note: this list can also be viewed from the command line using `vault path-help pki/roles/<ROLE_NAME>`):




### Import Queue
After a certificate has been signed by the Vault CA it is added to the import queue. Processing of certificates in the queue
begins automatically and will run continuously from that point until the plugin exits. 

At any time you can view the contents of the import queue (by certificate serial number) using the following command:
```
vault list pki/import-queue
```
Also you can check certificates for a specific role by running:
```
vault read pki/import-queue/<ROLE_NAME>
```

[![asciicast](https://asciinema.org/a/ydAXoUiZFmMcmXfSvqQSxJyJa.svg)](https://asciinema.org/a/ydAXoUiZFmMcmXfSvqQSxJyJa)

### Testing Visibility

1. Initialize the Vault PKI certificate authority (if not yet initialized):
    ```
    vault write pki/root/generate/internal common_name="Vault Test Root CA" ttl=8760h
    ```

1. Enroll a certificate using the CA:
    ```
    vault write pki/issue/venafi-role common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"
    ```

1. You should see something like this in the Vault log:
   ```
   2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi: 2018/11/14 17:18:59 Job id: 1 ### Certificate imported:
   2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:  {
   2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "CertificateDN": "\\VED\\Policy\\DevOps\\Vault Monitor\\test.example.com",
   2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "CertificateVaultId": 9147083,
   2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "Guid": "{dffb26c2-4510-4965-89c0-4d64a04b80fa}"
   2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi: }
   ```

1. Check the result in Venafi:
    1. For Venafi Platform, navigate to the policy folder (zone) you specified when you created the role, and review
    the certificate that was created.
    1. For Venafi Cloud, navigate to the Venafi Cloud Risk Assessement certificate inventory page and use the 'Newly Discovered' filter to view
    certificates that were uploaded from Vault within the specified timeframe.

<!-- TODO: show example of separating permissions between InfoSec and DevOps -->
## Usage Example of Venafi Policy Enforcement

Following scenario assumes that you already started the Vault and mounted venafi plugin. If not, you can use instructions from 
quickstart or use demo scripts to start simple vault server with Consul (not recommended for production). To start demo server
run `make docker_server` command. 
After starting demo server, you will need to export VAULT_TOKEN with Root token and VAULT_ADDR variables
    ```
    export VAULT_TOKEN=<enter root token here>
    export VAULT_ADDR=http://127.0.0.1:8200
    ```

1.  Download linux binary of the plugin into pkg/bin folder or build it using `make dev_build` command

1.  Create a policy for the DevOps role to allow all activities with the PKI backend,
    the venafi-policy can be configured to only one particular Venafi Platform and zone::
    ```bash
    cat <<EOF> devops-policy.hcl
    path "pki/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }
    path "pki/venafi-policy/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
      allowed_parameters = {
        "tpp_url" = ["https://tpp.venafi.example:443/vedsdk"]
        "zone" = ["DevOps\\Vault Monitor"]
        "tpp_user" = []
        "tpp_password" = []
        "trust_bundle_file" = []
      }
    }
    EOF
        
    ```
    
1.  Create a policy from file:
    ```bash
    vault policy fmt devops-policy.hcl && \
    vault policy write devops-policy devops-policy.hcl
    ```
        
1.  Create a token mapped to devops policy:
    ```bash
    vault token create -policy=devops-policy -display-name=devops
    ```  

1. Copy token from Key and export it into the VAULT_TOKEN variable in the same way as you did with root.
    ```bash
    export VAULT_TOKEN=<enter devops token here>
    ```
1. Create a test policy or zone in Venafi Platform or Cloud and allow only the example.com domain
     
1. Configure venafi policy with DevOps user (you can try to change zone or tpp_url parameter to make sure
that restrictions are working):
    ```bash
    vault write pki/venafi-policy/default \
            tpp_url="https://tpp.venafi.example:443/vedsdk" \
            tpp_user="local:admin" \
            tpp_password="password" \
            zone="DevOps\\Vault Monitor" \
            trust_bundle_file="/opt/venafi/bundle.pem"
    ```

    You should see policy on the output.
    
1. Try to sign internal CA with wrong domain:
    ```
    vault write pki/root/generate/internal common_name="vault.google.com" ttl=8760h
    ```
    
    You should see error
    
1. Sign CA with allowed domain:
    ```
    vault write pki/root/generate/internal common_name="vault.example.com" ttl=8760h
    ```

1. Create a [PKI role](https://www.vaultproject.io/docs/secrets/pki/index.html) for the `pki` backend:
    ```
    vault write pki/roles/venafi-role \
        generate_lease=true ttl=1h max_ttl=1h \
        allowed_domains=venafi.com,example.com \
        allow_subdomains=true
    ```
    
1. Enroll wrong certificate:
    ```
    vault write pki/issue/venafi-policy common_name="test.venafi.com" alt_names="test-1.venafi.com,test-2.venafi.com"
    ```
    
1. Enroll normal certificate:
    ```
    vault write pki/issue/venafi-policy common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"    
    ```    
    
1. Enroll wrong certificate using CSR sign:
    ```
    openssl req -new -newkey rsa:2048 -nodes -out test_wrong_wrong.csr -keyout test_wrong_wrong.key -subj "/C=/ST=/L=/O=/OU=/CN=test.wrong.wrong"
    vault write pki/sign/venafi-policy csr=@test_wrong_wrong.csr
    ```    

1. Enroll normal certificate:
    ```
    openssl req -new -newkey rsa:2048 -nodes -out test_example_com.csr -keyout test_example_com.key -subj "/C=/ST=/L=/O=/CN=test.example.com"
    vault write pki/sign/venafi-policy csr=@test_example_com.csr
    ```

1. Delete the policy:
    ```
    vault delete pki/venafi-policy/default
    ```
    
1. Try to enroll certificate again:
    ```
    vault write pki/sign/venafi-policy csr=@test_example_com.csr
    ```
    It will fail
    
1. Create second policy:
    ```bash
    vault write pki/venafi-policy/second \
                tpp_url="https://tpp.venafi.example:443/vedsdk" \
                tpp_user="local:admin" \
                tpp_password="password" \
                zone="DevOps\\Vault Monitor" \
                trust_bundle_file="/opt/venafi/bundle.pem"
    ```    
    
1. Reconfigure the role to use seond policy instead of default:
    ```bash
    vault write pki/roles/venafi-role \
            generate_lease=true ttl=1h max_ttl=1h \
            allowed_domains=venafi.com,example.com \
            allow_subdomains=true
            venafi_check_policy=second
    ```    
1. Try to enroll certificate again:
    ```
    vault write pki/sign/venafi-policy csr=@test_example_com.csr
    ```
    Now it should work.
        


### See it at asciinema:

[![asciicast](https://asciinema.org/a/T6DKJ1gu2B2s22AIglJCsxTkd.svg)](https://asciinema.org/a/T6DKJ1gu2B2s22AIglJCsxTkd)


### Venafi Policy Synchronization
You can automatically synchronize PKI role values (e.g. OU, O, L, ST, and C) with Venafi policy. To do so, simply set the
`venafi_sync_policy` parameter to the Venafi enforcement policy name as shown in the following example:  
 
1. Configure Venafi policy:

    ```
    vault write pki/venafi-policy/tpp \ 
        tpp_url="https://tpp.example.com/vedsdk" \
        tpp_user="admin" \
        tpp_password="strongPassword" \ 
        zone="devops\\vcert" \
        trust_bundle_file="/opt/venafi/bundle.pem"
    ```

1. Create a role with the sync parameter:

    ```
    vault write pki/roles/tpp-sync-role \
        venafi_sync_policy="tpp"
    ```

1. After approximately 15 seconds the role values should be synchronized with Venafi policy:

    ```
    $ vault read pki/roles/tpp-sync-role
    Key                                   Value
    ---                                   -----
    .....
    country                               [US]
    .....
    locality                              [Salt Lake]
    .....
    organization                          [Venafi Inc.]
    ou                                    [Integrations]
    ......
    province                              [Utah]
    ......
    ```
    
1. To check which roles are synchronizing with Venafi policy, read from the _pki/venafi-sync-policies_ path:

    ```
    $ vault read pki/venafi-sync-policies
    Key     Value
    ---     -----
    keys    [role: tpp-sync-role sync policy: tpp]
    ```

## Developer Quickstart (Linux only)

1. We supportiong Go versions from 1.11

1. Export your Venafi Platform configuration variables:
    ```
    export TPP_USER=<WebSDK User for Venafi Platform, e.g. "admin">
    export TPP_PASSWORD=<Password for WebSDK User, e.g. "password">
    export TPP_URL=<URL of Venafi Platform WebSDK, e.g. "https://venafi.example.com/vedsdk">
    export TPP_ZONE=<Name of the policy folder under which all certificates will be requested>
    ```

    * Use double-quotes if there are spaces in the policy folder name: `export TPP_ZONE="Vault Import"`
    * Double escape backslashes (4 total) if you have nested policy folders: `export TPP_ZONE="DevOps\\\\Vault Import"`

1. Run `make dev_server` to start Vault server.

1. Run `make dev` to build and enable the `vault-pki-monitor-venafi` plugin.

1. Run `make import` to sign a random certificate and import it to the Venafi Platform.
