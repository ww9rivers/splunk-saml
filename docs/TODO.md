# To-Do List

- [x] Revise the configuration file:
  - [x] Add a `hostname` field for each instance.
  - [x] If missing, construct `managementUrl` as `https://<hostname>:8089` and `webUrl` as `https://<hostname>:8000`.
  - [x] Add `loadBalancerHostname`, which maps to Splunk's SAML `fqdn` setting and the **Load balancer hostname or IP address** field in Splunk Web.
  - [x] Confirm the purpose of `certificate`: it is the IdP SAML signing certificate, not the Splunk host's TLS certificate, so the conditional path conversion is not applicable.
- [x] Use IdP metadata as the normal signing-certificate source:
  - [x] Retire the required inline `certificate` field.
  - [x] Add optional manual `idpCertificatePath` support mapped to Splunk's `idpCertPath`.
  - [x] Retrieve and validate all signing certificates in IdP metadata, including multiple rollover certificates.
