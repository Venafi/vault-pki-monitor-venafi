# Venafi PKI plugin backend for monitoring HashiCorp Vault

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

This solution allows [HashiCorp Vault](https://www.vaultproject.io/) users to provide their Information Security organization visibilty into certificate issuance.  Vault issued certificates are automatically forwarded to the [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) which enables risk assessment, incident response, and auditing that ensures compliance with enterprise security policy.  The [secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html) component is the original HashiCorp Vault.

## Dependencies

* HashiCorp Vault: https://www.vaultproject.io/downloads.html

## Requirements for use with Trust Protection Platform

1. The WebSDK user that Vault will be using to authenticate with the Venafi Platform has been granted view, read, write, and create permission to their policy folder.

### Establishing Trust between Vault and Trust Protection Platform

It is not common for the Venafi Platform's REST API (WebSDK) to be secured using a certificate issued by a publicly trusted CA, therefore establishing trust for that server certificate is a critical part of your configuration.  Ideally this is done by obtaining the root CA certificate in the issuing chain in PEM format and copying that file to your Vault server (e.g. /opt/venafi/bundle.pem).  You then reference that file using the 'trust_bundle_file' parameter whenever you create a new PKI role in your Vault.

## Quickstart, Step by Step

1. Familiarize yourself with the [HashiCorp Vault Plugin System](https://www.vaultproject.io/docs/internals/plugins.html)

2. Download the current `vault-pki-monitor-venafi` release package for your operating system and unzip the plugin to the `/etc/vault/vault_plugins` directory (or a custom directory of our choosing):
    ```
    wget https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/0.0.2/vault-pki-monitor-venafi_0.0.3_linux.zip
    unzip vault-pki-monitor-venafi_0.0.3_linux.zip
    mv vault-pki-monitor-venafi /etc/vault/vault_plugins
    ```

3. Configure the plugin directory for your Vault by specifying it in the startup configuration file:
    ```
    echo 'plugin_directory = "/etc/vault/vault_plugins"' > vault-config.hcl
    ```

4. Start your Vault (note: if you don't have working configuration you can start it in dev mode):
    ```
    vault server -log-level=debug -dev -config=vault-config.hcl
    ```

[![demo](https://asciinema.org/a/VQ1f9Xdmftz5FhtX0GP1bblSg.png)](https://asciinema.org/a/VQ1f9Xdmftz5FhtX0GP1bblSg?autoplay=1)

5.  Export the VAULT_ADDR environment variable so that the Vault client will interact with the local Vault:
    ```
    export VAULT_ADDR=http://127.0.0.1:8200
    ```

6. Get the SHA-256 checksum of `vault-pki-monitor-venafi` plugin binary:
    ```
    SHA256=$(shasum -a 256 /etc/vault/vault_plugins/vault-pki-monitor-venafi | cut -d' ' -f1)
    ```

7. Add the `vault-pki-monitor-venafi` plugin to the Vault system catalog:
    ```
    vault write sys/plugins/catalog/vault-pki-monitor-venafi sha_256="${SHA256}" command="vault-pki-monitor-venafi"
    ```

8. Enable the secrets backend for the `vault-pki-monitor-venafi` plugin:
    ```
    vault secrets enable -path=venafi-pki -plugin-name=vault-pki-monitor-venafi plugin
    ```

9. Create a [PKI role](https://www.vaultproject.io/docs/secrets/pki/index.html) for the `venafi-pki` backend making sure the `tpp_import` option is enabled:
    ```
    vault write venafi-pki/roles/vault-monitor \
        tpp_import=true \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Vault Monitor" \
        trust_bundle_file="/opt/venafi/bundle.pem" \
        generate_lease=true store_by_cn=true store_pkey=true store_by_serial=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```

The following options are supported (note: this list can also be viewed from the command line using `vault path-help vault-pki-monitor-venafi/roles/<ROLE_NAME>`):

| Parameter           | Type    | Description                                                                   | Default   |
| ------------------- | ------- | ------------------------------------------------------------------------------| --------- |
| `tpp_import`        | bool    | Controls whether certificates are forwarded to the Venafi Platform            | `true`    |
| `zone`              | string  | Venafi Platform policy folder where certificates will be imported             | "Default" | 
| `tpp_url`           | string  | Venafi URL (e.g. "https://tpp.venafi.example:443/vedsdk")                     |           |
| `tpp_username`      | string  | Venafi Platform WebSDK account username                                       |           |
| `tpp_password`      | string  | Venafi Platfrom WebSDK account password                                       |           |
| `trust_bundle_file` | string  | PEM trust bundle for Venafi Platform server certificate                       |           |
| `tpp_import_timeout`| int     | Maximum wait in seconds before re-attempting certificate import from queue    | 15        |
| `tpp_import_workers`| int     | Maximum number of concurrent threads to use for VCert import                  | 3         |

10. Initialize the Vault PKI certificate authority:
    ```
    vault write venafi-pki/root/generate/internal common_name="Vault Test Root CA" ttl=8760h
    ```

11. Enroll a certificate using the CA:
    ```
    vault write venafi-pki/issue/vault-monitor common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"
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
After a certificate has been signed it is added to the import queue. Processing of certificates in the queue begins automatically and will run continuously from that point until the plugin exits.  You can also manually initiate import queue processing using the following command:
```
vault read venafi-pki/import-queue/<ROLE_NAME>
```

At any time you can view the contents of the import queue by certificate serial number using the following command:
```
vault list venafi-pki/import-queue
```

## Venafi Policy check (UNDER DEVELOPMENT)

Venafi policy check is a feature which allows to limit PKI role by Venafi Trust Protection Platform or Venafi Cloud policies.
Policy check is configured in venafi-policy path, you can restrict this path for InfoSec team only using Vault policies.

1. Write default venafi policy configuration into venafi-policy path:
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
        zone="Default" \
    ```

    TODO: add scheduled update script with prod ready security example here.

    Policy will be downloaded, parsed, saved into path and user will see output with parsed policy.
    After policy creation any requested certificate will be checked against it. If checks will not pass
    user will see error similar to standart PKI role checks i.e.:
    ```
    URL: PUT http://127.0.0.1:8200/v1/vault-pki-monitor-venafi/issue/domain.com
    Code: 400. Errors:

    * common name import-vl9kt.import.example.com not allowed by Venafi policy
    ```

1. Policy can be deleted by performing delete operation to the venafi-polict path:
    ```
    vault delete pki/venafi-policy
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
    vault write venafi-pki/roles/venafi \
        tpp_import=true \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Vault Monitor" \
        venafi_check_policy="another-policy" \
        trust_bundle_file="/opt/venafi/bundle.pem" \
        generate_lease=true store_by_cn=true store_pkey=true store_by_serial=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```

<!-- TODO: show example of separating permissions between InfoSec and DevOps -->

## Developer Quickstart (Linux only)

1. Export your Venafi Platform configuration variables:
    ```
    export TPPUSER=<WebSDK User for Venafi Platform, e.g. "admin">
    export TPPPASSWORD=<Password for WebSDK User, e.g. "password">
    export TPPURL=<URL of Venafi Platform WebSDK, e.g. "https://venafi.example.com/vedsdk">
    export TPPZONE=<Name of the policy folder under which all certificates will be requested>
    ```

    * Use double-quotes if there are spaces in the policy folder name: `export TPPZONE="Vault Import"`
    * Double escape backslashes (4 total) if you have nested policy folders: `export TPPZONE="DevOps\\\\Vault Import"`

2. Run `make dev_server` to start Vault server.

3. Run `make dev` to build and enable the `vault-pki-monitor-venafi` plugin.

4. Run `make import` to sign a random certificate and import it to the Venafi Platform.
