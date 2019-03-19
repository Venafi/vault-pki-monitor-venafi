# Venafi PKI plugin backend for monitoring HashiCorp Vault

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

This solution allows [HashiCorp Vault](https://www.vaultproject.io/) users to provide their
Information Security organization visibility into certificate issuance.
Vault issued certificates are automatically forwarded to the 
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) which enables
risk assessment, incident response, and auditing that ensures compliance with enterprise security policy.
The [secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html) component is the original HashiCorp Vault.

## Dependencies

* HashiCorp Vault: https://www.vaultproject.io/downloads.html

## Requirements for use with Trust Protection Platform

1. The WebSDK user that Vault will be using to authenticate with the Venafi Platform has been
 granted view, read, write, and create permission to their policy folder.

### Establishing Trust between Vault and Trust Protection Platform

It is not common for the Venafi Platform's REST API (WebSDK) to be secured using a certificate issued by a publicly trusted CA,
therefore establishing trust for that server certificate is a critical part of your configuration.
Ideally this is done by obtaining the root CA certificate in the issuing chain in PEM format and copying that file to
your Vault server (e.g. /opt/venafi/bundle.pem).  You then reference that file using the 'trust_bundle_file' parameter whenever you create
a new PKI role in your Vault.

## Quickstart. Enabling the plugin.

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

This plugin is a copy of [original Vault PKI plugin](https://www.vaultproject.io/docs/secrets/pki/index.html) with additional features
for integrating it with Venafi Platform and Cloud.

1. Download the current `vault-pki-monitor-venafi` release package for your operating system and checksum for the binary.
   There're two versions of binaries - optional and strict. In optional binary if Venafi policy is not configured no checks will be made.
   In strict if Venafi policy is not configured when you try to issue the certificate you will get error: 
   "policy data is nil. You need configure Venafi policy to proceed"
    ```
    curl -fOSL https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/0.3.1/vault-pki-monitor-venafi_0.3.1+59_linux_strict.zip
    curl -fOSL https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/0.3.1/vault-pki-monitor-venafi_0.3.1+59_linux_strict.SHA256SUM
    ```

1. Unzip the plugin binary and check it with sha256 
    ```
    unzip vault-pki-monitor-venafi_0.3.1+59_linux_strict.zip
    sha256sum -c vault-pki-monitor-venafi_0.3.1+59_linux_strict.SHA256SUM
    ```
1. Move it to the `/etc/vault/vault_plugins` directory (or a custom directory of your choosing):
    ```
    mv vault-pki-monitor-venafi_strict /etc/vault/vault_plugins
    ```
    
1. Configure the plugin directory for your Vault by specifying it in the startup configuration file:
    ```
    echo 'plugin_directory = "/home/arykalin/tmp/monitortest/vault_plugins"' > vault-config.hcl
    ```

1. Start your Vault (note: if you don't have working configuration you can start it in dev mode.):  
    **!Dev mode is only for first look or developement purposes. Don't use it in production!**
    ```
    vault server -log-level=debug -dev -config=vault-config.hcl
    ```

1.  Export the VAULT_ADDR environment variable so that the Vault client will interact with the local Vault:
    ```
    export VAULT_ADDR=http://127.0.0.1:8200
    ```

1. Get the SHA-256 checksum of `vault-pki-monitor-venafi` plugin binary from checksum file:
    ```
    SHA256=$(cut -d' ' -f1 vault-pki-monitor-venafi_0.3.1+59_linux_strict.SHA256SUM)
    echo $SHA256
    ```

1. Add the `vault-pki-monitor-venafi` plugin to the Vault system catalog:
    ```
    vault write sys/plugins/catalog/vault-pki-monitor-venafi_strict sha_256="${SHA256}" command="vault-pki-monitor-venafi_strict"
    ```

1. Enable the secrets backend for the `vault-pki-monitor-venafi` plugin:
    ```
    vault secrets enable -path=pki -plugin-name=vault-pki-monitor-venafi_strict plugin
    ```

[![asciicast](https://asciinema.org/a/vmo1iE4fj3bDQFOByCSVH5h4D.svg)](https://asciinema.org/a/vmo1iE4fj3bDQFOByCSVH5h4D)

## Quickstart. Venafi Policy check

Venafi Policy Check limits the PKI role based on Venafi Trust Protection Platform policies or Venafi Cloud zones.
Policy check is configured in venafi-policy path, you can restrict this path for InfoSec team only using Vault policies.

1. Write default Venafi policy configuration into venafi-policy path:
    1. For Trust Protection Platform:
    ```
    vault write pki/venafi-policy/default \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Default" \
        trust_bundle_file="/opt/venafi/bundle.pem"
    ```
    1. For the Cloud:
    ```
    vault write pki/venafi-policy/default \
        token="xxxxx-xxxxx-xxxxx-xxxxx-xxxxxx" \
        zone="Default"
    ```

    Following options are supported(note: this list can also be viewed from the command line using `vault path-help pki/venafi-policy/default`):  
    | Parameter           | Type    | Description                                                                   | Default   |
    | ------------------- | ------- | ------------------------------------------------------------------------------| --------- |
    |apikey
    |ext_key_usage
    |name
    |
    
    You also 
    <!--TODO: add scheduled update script with prod ready security example here.-->

    Policy will be downloaded, parsed, saved into path and user will see output with parsed policy.
    After policy creation, any requested certificate will be checked against it. If checks fail to pass
    user will see error similar to standard PKI role checks i.e.:
    ```
    URL: PUT http://127.0.0.1:8200/v1/vault-pki-monitor-venafi/issue/domain.com
    Code: 400. Errors:

    * common name import-vl9kt.import.example.com not allowed by Venafi policy
    ```

1. You can read content of the policy using read operation:
    ```
    vault read pki/venafi-policy/default/policy
    ```
    
1. You can read connection configuration:
    ```
    vault read pki/venafi-policy/default
    ```
        
1. You can use multiple policies for different roles.
    1. Write another policy configuration:
    ```
    vault write pki/venafi-policy/another-policy \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Another policy" \
        trust_bundle_file="/opt/venafi/bundle.pem"
    ```
    1. Specify policy on role configuration:
    ```
    <!--TODO: rename tpp_import to venafi_import-->
    vault write pki/roles/venafi-role \
        zone="DevOps\\Vault Monitor" \
        venafi_check_policy="another-policy" \
        trust_bundle_file="/opt/venafi/bundle.pem" \
        generate_lease=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```

1. Venafi Policy can be deleted by performing delete operation to the venafi-polict path:
    ```
    vault delete pki/venafi-policy
    ```
    
[![asciicast](https://asciinema.org/a/exZfzOOFyuxjvvQ61RE74B1LC.svg)](https://asciinema.org/a/exZfzOOFyuxjvvQ61RE74B1LC)    
    
## Quickstart. Enabling Venafi Platform Import feature

1. Create a [PKI role](https://www.vaultproject.io/docs/secrets/pki/index.html) for the `pki` backend making sure the `tpp_import` option is enabled:
    ```
    vault write pki/roles/tpp-import-role \
        tpp_import=true \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Vault Monitor" \
        trust_bundle_file="/opt/venafi/bundle.pem" \
        generate_lease=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```

The following options are supported (note: this list can also be viewed from the command line using `vault path-help pki/roles/<ROLE_NAME>`):

| Parameter           | Type    | Description                                                                   | Default   |
| ------------------- | ------- | ------------------------------------------------------------------------------| --------- |
| `tpp_import`        | bool    | Controls whether certificates are forwarded to the Venafi Platform            | `true`    |
| `zone`              | string  | Venafi Platform policy folder where certificates will be imported             | "Default" |
| `tpp_url`           | string  | Venafi URL (e.g. "https://tpp.venafi.example:443/vedsdk")                     |           |
| `tpp_username`      | string  | Venafi Platform WebSDK account username                                       |           |
| `tpp_password`      | string  | Venafi Platform WebSDK account password                                       |           |
| `trust_bundle_file` | string  | PEM trust bundle for Venafi Platform server certificate                       |           |
| `tpp_import_timeout`| int     | Maximum wait in seconds before re-attempting certificate import from queue    | 15        |
| `tpp_import_workers`| int     | Maximum number of concurrent threads to use for VCert import                  | 3         |
|`venafi_check_policy`|string   | Which Venafi policy check to use                                              | "default" |

10. Initialize the Vault PKI certificate authority (if not yet initialized):
    ```
    vault write pki/root/generate/internal common_name="Vault Test Root CA" ttl=8760h
    ```

11. Enroll a certificate using the CA:
    ```
    vault write pki/issue/tpp-import-role common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"
    ```

12. Check the Vault log and you should see something like this:
```
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi: 2018/11/14 17:18:59 Job id: 1 ### Certificate imported:
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:  {
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "CertificateDN": "\\VED\\Policy\\DevOps\\Vault Monitor\\test.example.com",
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "CertificateVaultId": 9147083,
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "Guid": "{dffb26c2-4510-4965-89c0-4d64a04b80fa}"
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi: }
```

[![demo](https://asciinema.org/a/FrX6zj2MwbYLjop9ceIwUFNVU.png)](https://asciinema.org/a/FrX6zj2MwbYLjop9ceIwUFNVU?autoplay=1)

13. Log into the Venafi Platform, navigate to the policy folder (zone) you specified when you created the role, and review the certificate that was created.

## Import Queue
After a certificate has been signed it is added to the import queue. Processing of certificates in the queue begins automatically
and will run continuously from that point until the plugin exits.  You can also manually initiate import queue processing using the following command:
```
vault read pki/import-queue/<ROLE_NAME>
```

At any time you can view the contents of the import queue by certificate serial number using the following command:
```
vault list pki/import-queue
```

<!-- TODO: show example of separating permissions between InfoSec and DevOps -->
## Venafi Policy usage scenario

Following scenario assumes that you already started the Vault and mounted venafi plugin. If not, you can use instructions from 
quickstart or use demo scripts to start simple vault server with consul (not recommended for production). To start demo server
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
    
1. Sing CA with allowed domain:
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

<!--TODO: add delete policy to usage scenario-->

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
