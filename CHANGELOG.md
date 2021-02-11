## v0.9.0 (February 10, 2021)

Updated Venafi Cloud integration to use OutagePREDICT instead of DevOpsACCELERATE.

## v0.8.3 (January 23, 2021)

Enhanced monitoring behavior to allow limiting Venafi import to certificates a Vault CA issues that do not comply with Venafi policy.

## v0.8.2 (December 11, 2020)

Updated credential requirements for Trust Protection Platform to support initialization with only a `refresh_token`.

## v0.8.1 (October 30, 2020)

Introduced Venafi Secret for specifying Venafi connection and authentication settings.

Added support for token authentication with Trust Protection Platform (API Application ID "hashicorp-vault-monitor-by-venafi").

Deprecated legacy username/password for Trust Protection Platform.

Resolved Vault Enterprise issue involving behavior when interacting with Performance Standby or Performance Secondary.

Added option to automatically synchronize PKI role settings with Venafi Policy.

Updated Venafi Policy to solely govern the roles to which it enforces policy and default values, and roles from which it imports certificates into Venafi.

Dropped support for `apikey`, `tpp_url`, `tpp_username`, `tpp_password`, `zone`, `trust_bundle_file`, `venafi_import`, `venafi_import_timeout`, `venafi_import_workers`, and `venafi_check_policy` role settings.

Added Source Application Tagging for Trust Protection Platform and Venafi Cloud.

## v0.6.0 (February 19, 2020)

Dropped support for previously deprecated `tpp_import`, `tpp_import_timeout`, and `tpp_import_workers` parameters.

## v0.5.5 (February 5, 2020)

Resolved issue where Vault stopped issuing certifcates after importing hundreds/thousands of certificates into Venafi.

## v0.5.3 (January 20, 2020)

Resolved issue where secrets engine would try indefinitely to import certificates that were rejected because they don't comply with policy (i.e. key reused)

## v0.5.2 (January 10, 2020)

Resolved issue involving Venafi Policy enforcement of key size

## v0.5.0+311 (September 13, 2019)

Resolved issue involving Venafi Policy enforcement of domains with TPP.

## v0.4.0+181 (May 16, 2019)

Resolved issue with plugin running Vault on Windows.

## v0.4.0 (April 25, 2019)

Added visibility into certificates issued by the Vault CA for Venafi Cloud. 

## v0.3.2 (April 11, 2019)

Enhanced secrets engine to start import queue automatically after Vault restart.

Offer "strict" and "optional" plugin binaries to choose whether compliance with Venafi Policy is required ("optional" targeting test/dev use cases). 

## v0.3.0 (March 16, 2019)

Added Venafi Policy Enforcement to check certificate requests for compliance with Venafi Policy.

## v0.1.0 (February 6, 2019)

Initial Release, provides visibility into certificates issued by the Vault CA for Trust Protection Platform.
