[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 18.2+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2018.2+%20%26%20VaaS-f9a90c)  
:warning: _**This community-supported open source project has reached its END-OF-LIFE, and as of May 30th 2025, this project is deprecated and will no longer be maintained**.  Please use **[Venafi PKI Secrets Engine for HashiCorp Vault](https://github.com/Venafi/vault-pki-backend-venafi)**_

# Venafi PKI Monitoring Secrets Engine for HashiCorp Vault

This solution allows [HashiCorp Vault](https://www.vaultproject.io/) users to provide their
Information Security organization proactive policy enforcement and visibility into certificate issuance.
Vault issued certificates can be automatically forwarded to 
[Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform) or
[Venafi as a Service](https://www.venafi.com/venaficloud) which enables risk assessment, incident response, and
auditing that ensures compliance with enterprise security policy.
The [secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html) component was sourced from the
original HashiCorp Vault PKI secrets engine.

## Dependencies

* HashiCorp Vault: https://www.vaultproject.io/downloads.html

### Venafi Trust Protection Platform Requirements

1. For policy enforcement, the Venafi WebSDK user that Vault will be using needs
   to have been granted view and read permissions to the policy folder from which
   Venafi policy will be obtained.
1. For issuance visibility, the Venafi WebSDK user that Vault will be using needs
   to have been granted write and create permission to the policy folder where
   Vault issued certificates will be imported, and the _Allow Users to Import
   Duplicate Certificates and Reuse Private Keys_ policy of that folder needs to be
   set to 'Yes' to ensure that all certificates issued by the Vault can be imported.

#### Trust between Vault and Trust Protection Platform

The Trust Protection Platform REST API (WebSDK) must be secured with a
certificate. Generally, the certificate is issued by a CA that is not publicly
trusted so establishing trust is a critical part of your setup.

Two methods can be used to establish trust. Both require the trust anchor
(root CA certificate) of the WebSDK certificate. If you have administrative
access, you can import the root certificate into the trust store for your
operating system. If you don't have administrative access, or prefer not to
make changes to your system configuration, save the root certificate to a file
in PEM format (e.g. /opt/venafi/bundle.pem) and reference it using the
`trust_bundle_file` parameter whenever you create or update a PKI role in your
Vault.

### Venafi as a Service Requirements

If you are using Venafi as a Service, verify the following:

- The Venafi as a Service REST API at [https://api.venafi.cloud](https://api.venafi.cloud/swagger-ui.html)
is accessible from the systems where Vault will be running.
- You have successfully registered for a Venafi as a Service account, have been granted at least the
"Resource Owner" role, and know your API key.
- A CA Account and Issuing Template exist and have been configured with:
    - Recommended Settings values for:
        - Organizational Unit (OU)
        - Organization (O)
        - City/Locality (L)
        - State/Province (ST)
        - Country (C)
    - Issuing Rules that:
        - (Recommended) Limits Common Name and Subject Alternative Name to domains that are allowed by your organization
        - (Recommended) Restricts the Key Length to 2048 or higher
        - (Recommended) Does not allow Private Key Reuse
- An Application exists where you are among the owners, and you know the Application name.
- An Issuing Template is assigned to the Application, and you know its API Alias.

## Setup

This plugin was originally sourced from the
[built-in Vault PKI secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html)
and enhanced with features for integrating with Trust Protection Platform and Venafi as a Service.

1. Create the [directory](https://www.vaultproject.io/docs/internals/plugins#plugin-directory)
   where your Vault server will look for plugins (e.g. /etc/vault/vault_plugins).
   The directory must not be a symbolic link. On macOS, for example, /etc is a
   link to /private/etc. To avoid errors, choose an alternative directory such
   as /private/etc/vault/vault_plugins.

1. Download the latest `vault-pki-monitor-venafi` [release package](../../releases/latest) for
   your operating system. There are two versions, optional and script. The "optional" version
   allows certificates to be issues by the Vault CA when there is no Venafi policy applied
   whereas the "strict" version will return an error. Note that the URL for the zip file,
   referenced below, changes as new versions of the plugin are released.

    ```text
    $ wget -q https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/v0.0.1/venafi-pki-monitor_v0.0.1_linux_strict.zip
    ```

   :pushpin: **NOTE**: Release binaries are built and tested using the latest generally
   available version of Vault at the time.  Backward compatibility with older versions of Vault
   is typical but not confirmed by testing.

1. Compare the checksum of the package to the listed value on the GitHub release page.

    ```text
    $ sha256sum venafi-pki-monitor_v0.0.1_linux_strict.zip
    ```

1. Unzip the binary to the plugin directory.

    ```text
    $ unzip venafi-pki-monitor_v0.0.1_linux_strict.zip
    $ mv venafi-pki-monitor /etc/vault/vault_plugins
    ```

1. Update the Vault [server configuration](https://www.vaultproject.io/docs/configuration/)
   to specify the plugin directory:

    ```text
   plugin_directory = "/etc/vault/vault_plugins"
   ```

   :pushpin: **NOTE**: If plugin directory is a symbolic link, Vault responds
   with an error[:bookmark:](https://groups.google.com/forum/#!topic/vault-tool/IVYLA3aH72M).
   If you're configuring on a MacBook, /etc is default symlinked to /private/etc. To
   prevent the error from occurring, change the `plugin_directory` to a non-symlinked
   directory. For example "/private/etc/vault/vault_plugins". If you make this change,
   keep it in mind as you go through the remaining steps.

1. Start your vault using the [server command](https://www.vaultproject.io/docs/commands/server).

1. Get the SHA-256 checksum of the `venafi-pki-monitor` plugin binary (should be the same value 
   found in the `venafi-pki-monitor.SHA256SUM` file that accompanied the plugin in the zip file): 

    ```text
    $ SHA256=$(sha256sum /etc/vault/vault_plugins/venafi-pki-monitor |cut -d' ' -f1)
    ```

1. Register the `venafi-pki-monitor` plugin in the Vault 
   [system catalog](https://www.vaultproject.io/docs/internals/plugins#plugin-catalog):

   ```
   $ vault write sys/plugins/catalog/secret/venafi-pki-monitor \
       sha_256="${SHA256}" command="venafi-pki-monitor"

   Success! Data written to: sys/plugins/catalog/secret/venafi-pki-monitor
   ```

   :pushpin: **NOTE**: If you get an error that says "can not execute files
    outside of configured plugin directory", it's probably because you didn't set the
    plugin directory correctly with a non-symlinked directory as mentioned earlier. Also,
    make sure this change is reflected when calling for the SHA-256 checksum.

1. Enable the secrets engine for the `venafi-pki-monitor` plugin:

   ```text
   $ vault secrets enable -path=pki -plugin-name=venafi-pki-monitor plugin

   Success! Enabled the venafi-pki-monitor secrets engine at: pki/
   ```

1. Configure a Venafi secret that maps a name in Vault to connection and authentication
   settings for retrieving certificate policy and importing certificates into Venafi. The
   zone is a policy folder for Trust Protection Platform or an Application with Issuing
   Template alias for Venafi as a Service. Obtain the `access_token` and `refresh_token`
   for Trust Protection Platform using the
   [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#obtaining-an-authorization-token)
   (`getcred` action with `--client-id "hashicorp-vault-monitor-by-venafi"` and
   `--scope "certificate:manage,discover"`) or the Platform's Authorize REST API method. 

   **Trust Protection Platform**:

   ```
   $ vault write pki/venafi/tpp \
       url="https://tpp.example.com" trust_bundle_file="/path/to/bundle.pem" \
       access_token="tn1PwE1QTZorXmvnTowSyA==" refresh_token="MGxV7DzNnclQi9CkJMCXCg=="
   ```

   :pushpin: **NOTE**: Supplying a `refresh_token` allows the secrets engine to
   automatically obtain new tokens and operate without interruption whenever the
   `access_token` expires. This behavior is important to understand because it 
   may require you to provide a new `access_token` and `refresh_token` if you need
   to modify the Venafi secret in the future (i.e. depending upon whether the
   original set of tokens has been refreshed by the secrets engine plugin).

   **Venafi as a Service**:

   ```
   $ vault write pki/venafi/vaas apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   ```

   Following options are supported (note: this list can also be viewed
   from the command line using `vault path-help pki/venafi/default`):

   | Parameter             | Type   | Description                                                                         | Example   |
   | --------------------- | ------ | ----------------------------------------------------------------------------------- | --------- |
   |`access_token`         |string  | Trust Protection Platform access token for the "hashicorp-vault-monitor-by-venafi" API Application |`tn1PwE1QTZorXmvnTowSyA==`|
   |`apikey`               |string  | Venafi as a Service API key                                                         |`142231b7-cvb0-412e-886b-6aeght0bc93d`|
   |`url`                  |string  | Venafi service URL, generally only applicable to Trust Protection Platform          |`https://tpp.venafi.example`|
   |`refresh_token`        |string  | Refresh Token for Venafi Platform.                                                  |`MGxV7DzNnclQi9CkJMCXCg==`|
   |`tpp_password`         |string  | **[DEPRECATED]** Trust Protection Platform WebSDK password, use `access_token` if possible |`somePassword?`|
   |`tpp_user`             |string  | **[DEPRECATED]** Trust Protection Platform WebSDK username, use `access_token` if possible |`admin`|
   |`trust_bundle_file`    |string  | Text file containing trust anchor certificates in PEM format, generally required for Trust Protection Platform |`"/path/to/chain.pem"`|
   |`zone`                 |string  | Policy folder for TPP or Application name and Issuing Template API Alias for VaaS (e.g. "Business App\Enterprise CIT") to be used when no `zone` is specified by the venafi-policy |`testpolicy\\vault`|

1. Configure a default Venafi policy that will only enable issuance of policy 
   compliant certificate for all PKI roles in the path.

   **Trust Protection Platform**:

   ```
   $ vault write pki/venafi-policy/default venafi_secret="tpp" zone="DevOps\\Default"
   ```

   **Venafi as a Service**:

   ```
   $ vault write pki/venafi-policy/default \
       venafi_secret="vaas" zone="Business App\\Enterprise CIT"
   ```

   The following options are supported (note: this list can also be viewed
   from the command line using `vault path-help pki/venafi-policy/default`):

   | Parameter             | Type   | Description                                                                         | Example   |
   | --------------------- | ------ | ----------------------------------------------------------------------------------- | --------- |
   |`auto_refresh_interval`|int     | Interval of Venafi policy update in seconds. Set to 0 to disable automatic refresh  | 0 | 
   |`defaults_roles`       |string  | List of roles where default values from Venafi will be applied                      |`tpp`|
   |`enforcement_roles`    |string  | List of roles where Venafi policy enforcement is enabled                            |`tpp`|
   |`ext_key_usage`        |string  | A comma-separated string of allowed extended key usages                             |`ServerAuth,ClientAuth`|
   |`import_roles`         |string  | List of roles where issued certificates will be imported into the Venafi `zone`     |`tpp`|
   |`import_timeout`       |int     | Maximum wait in seconds before re-attempting certificate import from queue          | 15 |
   |`import_workers`       |int     | Maximum number of concurrent threads to use for Venafi import                       | 5 |
   |`zone`                 |string  | Policy folder for TPP or Application name and Issuing Template API Alias for VaaS (e.g. "Business App\Enterprise CIT")|`testpolicy\\vault`|

1. Configure a [role](https://www.vaultproject.io/api-docs/secret/pki#create-update-role) with which you want to use for enforcing certificate policy.

    ```text
    $ vault write pki/roles/venafi-role generate_lease=true ttl=1h max_ttl=1h allow_any_name=true
    ```

1. Update the Venafi policy and add the created role to the defaults and enforcement lists.

    **Trust Protection Platform**:

    ```text 
    $ vault write pki/venafi-policy/default \
        defaults_roles="venafi-role" enforcement_roles="venafi-role" \
        venafi_secret="tpp" zone="DevOps\\Default"
    ```

    **Venafi as a Service**:

    ```text
    $ vault write pki/venafi-policy/default \
        defaults_roles="venafi-role" enforcement_roles="venafi-role" \
        venafi_secret="vaas" zone="Business App\\Enterprise CIT"
    ```

1. Create another Venafi policy for visibility. This will specify the zone where
   certificates issued by the Vault CA will be imported. Visibility is enabled at the
   policy level using the `import_roles` parameter.

    **Trust Protection Platform**:

    ```text
    $ vault write pki/venafi-policy/visibility \
        import_roles="venafi-role" venafi_secret="tpp" zone="DevOps\\Vault Monitor"
    ```

    **Venafi as a Service**:

    ```text
    $ vault write pki/venafi-policy/visibility \
        import_roles="venafi-role" venafi_secret="vaas" zone="Business App\\Enterprise CIT"
    ```

1. The final step is to make your PKI secrets engine a certificate authority by generating a new
   key pair and CSR which you will either sign locally (root CA) or have signed by another CA. 
   See steps 1 and 2 of the
   [Building Your Own Certificate Authority](https://developer.hashicorp.com/vault/tutorials/secrets-management/pki-engine)
   tutorial by HashiCorp.

## Usage

Venafi Policy limits the PKI role based on Trust Protection Platform policies or Venafi as a
Service Issuing Template rules.  Policy enforcement is configured using the special *venafi-policy* 
path which InfoSec teams can use to require compliance from a Vault CA. The Venafi monitoring plugin
can also add the resulting certificates to a queue for them to be imported into TPP or VaaS.

1. Generate a certificate by writing to the Vault CA and the Venafi role.

   ```text
   $ vault write pki/issue/venafi-role common_name="test.allowed.org" alt_names="test-1.allowed.org,test-2.allowed.org"
   ```

   If the request is policy compliant, the request will return a certificate successfully. This
   certificate will also be placed in the visibility import queue to be uploaded to the Venafi
   Trust Protection Platform.

1. Or sign a CSR from a file by writing to the `/sign` endpoint with the name of the role: 

    ```text
    $ vault write pki/sign/venafi-role csr=@test_example_com.csr
    ```

## Upgrading

To upgrade to a new version of this plugin, review the [release notes](../../releases/latest) to understand
the impact and then follow the [standard procedure](https://www.vaultproject.io/docs/upgrading/plugins). 
The following command will trigger a plug reload globally:

   ```text
   $ vault write sys/plugins/reload/backend plugin=venafi-pki-monitor scope=global

   Key          Value
   ---          -----
   reload_id    d8180af4-01e0-d4d8-10ce-0daf69fbb6ed
   ```

   :warning: **IMPORTANT:** Every member of a Vault cluster must be running with the same version
   of the plugin to avoid inconsistent, unexpected, and possibly erroneous results.

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Mozilla Public License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.

