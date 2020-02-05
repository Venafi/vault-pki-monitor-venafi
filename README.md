# Venafi PKI Monitoring Secrets Engine for HashiCorp Vault

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

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

It is not common for the Venafi Platform's REST API (WebSDK) to be secured using a certificate issued by a publicly trusted CA,
therefore establishing trust for that server certificate is a critical part of your configuration.
Ideally this is done by obtaining the root CA certificate in the issuing chain in PEM format and copying that file to
your Vault server (e.g. /opt/venafi/bundle.pem).  You then reference that file using the 'trust_bundle_file' parameter whenever you create
a new PKI role in your Vault.

## Quickstart: Enabling the Plug-in

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

This plugin is a copy of [original Vault PKI plugin](https://www.vaultproject.io/docs/secrets/pki/index.html) with additional features
for integrating it with Venafi Platform and Cloud.

1. Download the current `vault-pki-monitor-venafi` release zip package for your operating system and checksum for the binary.
   There are two versions of binaries, optional and strict. The "optional" allows certificates to be issued by the Vault CA
   when there is no Venafi policy applied whereas the "strict" will return the following error when there is no Venafi policy
   applied: *policy data is nil. You need configure Venafi policy to proceed*
    ```
    curl -fOSL https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/0.4.0%2B181/vault-pki-monitor-venafi_0.4.0+181_linux_strict.zip
    curl -fOSL https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/0.4.0%2B181/vault-pki-monitor-venafi_0.4.0+181_linux_strict.SHA256SUM
    ```

1. Unzip the plugin binary and check it with sha256 
    ```
    unzip vault-pki-monitor-venafi_0.4.0+181_linux_strict.zip
    sha256sum -c vault-pki-monitor-venafi_0.4.0+181_linux_strict.SHA256SUM
    ```
1. Move it to the `/etc/vault/vault_plugins` directory (or a custom directory of your choosing):
    ```
    mv vault-pki-monitor-venafi_strict /etc/vault/vault_plugins
    ```
    
1. Configure the plugin directory for your Vault by specifying it in the startup configuration file:
    ```
    echo 'plugin_directory = "/etc/vault/vault_plugins"' > vault-config.hcl
    ```

1. Start your Vault (note: if you don't have working configuration you can start it in dev mode.):  
    **Dev mode is only for educational or development purposes. Don't use it in production!**
    ```
    vault server -log-level=debug -dev -config=vault-config.hcl
    ```

1.  Export the VAULT_ADDR environment variable so that the Vault client will interact with the local Vault:
    ```
    export VAULT_ADDR=http://127.0.0.1:8200
    ```

1. Get the SHA-256 checksum of `vault-pki-monitor-venafi` plugin binary from checksum file:
    ```
    SHA256=$(cut -d' ' -f1 vault-pki-monitor-venafi_0.4.0+181_linux_strict.SHA256SUM)
    echo $SHA256
    ```

1. Add the `vault-pki-monitor-venafi` plugin to the Vault system catalog:
    ```
    vault write sys/plugins/catalog/secret/vault-pki-monitor-venafi_strict sha_256="${SHA256}" command="vault-pki-monitor-venafi_strict"
    ```

1. Enable the secrets backend for the `vault-pki-monitor-venafi` plugin:
    ```
    vault secrets enable -path=pki -plugin-name=vault-pki-monitor-venafi_strict plugin
    ```

[![asciicast](https://asciinema.org/a/vmo1iE4fj3bDQFOByCSVH5h4D.svg)](https://asciinema.org/a/vmo1iE4fj3bDQFOByCSVH5h4D)

### Running under Windows
 If you want to run plugin on Windows the following environment variables must specified to restrict the port that will be assigned to be from within a specific range. If not values are provided plugin will exit with error. For more information please see https://github.com/hashicorp/go-plugin/pull/111

  * `PLUGIN_MIN_PORT`: Specifies the minimum port value that will be assigned to the listener.
  * `PLUGIN_MAX_PORT`: Specifies the maximum port value that will be assigned to the listener.
 
## Quickstart: Enabling Venafi Policy Enforcement

Venafi Policy limits the PKI role based on Venafi Platform policies or Venafi Cloud zones.  Policy enforcement is
configured using the special *venafi-policy* path which InfoSec teams can use to require compliance from a Vault CA.

1. Write default Venafi policy configuration into *venafi-policy* path:
    1. For Trust Protection Platform:
    ```
    vault write pki/venafi-policy/default \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Default" \
        trust_bundle_file="/opt/venafi/bundle.pem"
    ```
    2. For the Cloud:
    ```
    vault write pki/venafi-policy/default \
        token="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
        zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
    ```

    Following options are supported (note: this list can also be viewed from the command line using `vault path-help pki/venafi-policy/default`):  
    
    | Parameter           | Type    | Description                                                                   | Example   |
    | ------------------- | ------- | ------------------------------------------------------------------------------| --------- |
    |`apikey`               |string   | API key for Venafi Cloud.                                                   |`142231b7-cvb0-412e-886b-6aeght0bc93d`|
    |`ext_key_usage`        |string   | A comma-separated string or list of allowed extended key usages.            |`ServerAuth,ClientAuth`|
    |`name`                 |string   | Name of the Venafi policy config. IS not set will be `default`              |`another-policy`|
    |`tpp_password`         |string   | Password for web API user                                                   |`password`|
    |`tpp_url`              |string   | URL of Venafi Platform.                                                     |`https://tpp.venafi.example/vedsdk`|
    |`tpp_user`             |string   | Web API user for Venafi Platform                                            |`admin`|
    |`trust_bundle_file`    |string   | Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.|`"/full/path/to/chain.pem"`|
    |`zone`                 |string   | Name of Venafi Platform policy or Venafi Cloud Zone ID.                     |`testpolicy\\vault`|
    
    <!--TODO: add scheduled update script with prod ready security example here.-->

    Policy will be downloaded from Venafi, parsed, saved under the specified path, and displayed to the user. After policy
    creation, any requested certificate will be checked against it.  If the request fails compliance with the policy, the
    user will see error similar to that of standard PKI role checking except stating "not allowed by Venafi policy":
    ```
    URL: PUT http://127.0.0.1:8200/v1/vault-pki-monitor-venafi/issue/domain.com
    Code: 400. Errors:

    * common name import-vl9kt.import.example.com not allowed by Venafi policy
    ```

1. The following command can be used to display the current Venafi policy:
    ```
    vault read pki/venafi-policy/default/policy
    ```
    
1. The Venafi configuration for the policy can be viewed using the following:
    ```
    vault read pki/venafi-policy/default
    ``` 
        
1. You can also use multiple Venafi policies by simply applying them to separate roles.
    1. Write another policy configuration:
    ```
    vault write pki/venafi-policy/another-policy \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Another policy" \
        trust_bundle_file="/opt/venafi/bundle.pem"
    ```
    2. Then specify the policy name when configuring the role:
    ```
    vault write pki/roles/venafi-role \
        venafi_check_policy="another-policy" \
        generate_lease=true ttl=1h max_ttl=1h \
        allow_any_name=true
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

| Parameter               | Type    | Description                                                                   | Default   |
| ----------------------- | ------- | ------------------------------------------------------------------------------| --------- |
| `venafi_import`         | bool    | Controls whether certificates are forwarded to the Venafi Platform or Venafi Cloud            | `true`    |
| `zone`                  | string  | Venafi Platform policy folder where certificates will be imported; for Venafi Cloud this is the endpoint that the certificates will be sent to.             | "Default" |
| `tpp_url`               | string  | Venafi URL (e.g. "https://tpp.venafi.example:443/vedsdk")                     |           |
| `tpp_username`          | string  | Venafi Platform WebSDK account username                                       |           |
| `tpp_password`          | string  | Venafi Platform WebSDK account password                                       |           |
| `trust_bundle_file`     | string  | PEM trust bundle for Venafi Platform server certificate                       |           |
| `venafi_import_timeout` | int     | Maximum wait in seconds before re-attempting certificate import from queue    | 15        |
| `venafi_import_workers` | int     | Maximum number of concurrent threads to use for VCert import                  | 12        |
| `venafi_check_policy`   | string  | Which Venafi policy check to use                                              | "default" |

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

## Developer Quickstart (Linux only)

1. We supportiong Go versions from 1.11

1. Export your Venafi Platform configuration variables:
    ```
    export TPPUSER=<WebSDK User for Venafi Platform, e.g. "admin">
    export TPPPASSWORD=<Password for WebSDK User, e.g. "password">
    export TPPURL=<URL of Venafi Platform WebSDK, e.g. "https://venafi.example.com/vedsdk">
    export TPPZONE=<Name of the policy folder under which all certificates will be requested>
    ```

    * Use double-quotes if there are spaces in the policy folder name: `export TPPZONE="Vault Import"`
    * Double escape backslashes (4 total) if you have nested policy folders: `export TPPZONE="DevOps\\\\Vault Import"`

1. Run `make dev_server` to start Vault server.

1. Run `make dev` to build and enable the `vault-pki-monitor-venafi` plugin.

1. Run `make import` to sign a random certificate and import it to the Venafi Platform.
