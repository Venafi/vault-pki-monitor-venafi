## v0.8.x (Upcoming Release)

Added support for token authentication with Trust Protection Platform (API Application ID "hashicorp-vault-monitor-by-venafi").

Deprecated legacy username/password for Trust Protection Platform.

Update to prevent certificates from being enrolled by Performance Standby or Performance Secondary (Vault Enterprise).

Added option to automatically synchronize PKI role settings with Venafi Policy.

Moved Venafi connection and authentication settings for import to venafi-policy.

Dropped support for `apikey`, `tpp_url`, `tpp_username`, `tpp_password`, `zone`, `trust_bundle_file`, `venafi_import`, `venafi_import_timeout`, `venafi_import_workers`, and `venafi_check_policy` role settings.

Source Application Tagging for Trust Protection Platform and Venafi Cloud.

## v0.6.0 (February 19, 2020)

Dropped support for previously deprecated `tpp_import`, `tpp_import_timeout`, and `tpp_import_workers` parameters.

## v0.5.5 (February 5, 2020)

Fix for issue where Vault stopped issuing certifcates after importing hundreds/thousands of certificates into Venafi.

## v0.5.3 (January 20, 2020)

Do not repeatedly attempt to import certificates if they are rejected because they don't comply with policy (i.e. key reused)

## v0.5.2 (January 10, 2020)

Fix for issue involving Venafi Policy enforcement of key size

## v0.5.0+311 (September 13, 2019)

Fix for issue involving Venafi Policy enforcement of domains with TPP.

## v0.4.0+181 (May 16, 2019)

Resolved issue with plugin running Vault on Windows.

## v0.4.0 (April 25, 2019)

Added visibility into certificates issued by the Vault CA for Venafi Cloud. 

## v0.3.2 (April 11, 2019)

Update to start import queue automatically after Vault restart.

Offer "strict" and "optional" plugin binaries to choose whether compliance with Venafi Policy is required ("optional" targeting test/dev use cases). 

## v0.3.0 (March 16, 2019)

Added Venafi Policy Enforcement to check certificate requests for compliance with Venafi Policy.

## v0.1.0 (February 6, 2019)

Initial Release, provides visibility into certificates issued by the Vault CA for Trust Protection Platform.
