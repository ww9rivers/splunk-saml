# splunk-saml

A command line app to assist in setting up Splunk Enterprise to use SAML single sign-on (SSO).

## Goal

Produce a CLI tool or a set of tools that can be used to configure Splunk Enterprise instances to use SAML for user authentication.
Microsoft Entra is the first target as the Identity Provider (IdP).

## Tech Stack

- Bun, TypeScript/JavaScript.
- Splunk REST and ACS API.

## To-Do

- First, plan the implementation by documenting the step-by-step process of Splunk SAML configuration.
  1. Should the first deliverable be only configuration documentation, or also a working CLI prototype?
     - The first deliverable need to be documentation plus a working CLI prototype.
  2. Which Splunk Enterprise versions and deployment types should be supported?
     - Targeting the latest version 10.4.2 would be a good starting point.
  3. Should the tool configure both Splunk and Microsoft Entra, or only Splunk using Entra-provided values?
     - The tool only needs to configure Splunk using Entra-provided values.
     - Document what are needed to also configure Entra with this tool or is it more appropriate to have create a different set of tools.
  4. How should the CLI authenticate to Splunk’s REST/ACS APIs?
     - The tool can use a modern JSON formatted file or something similar to store tokens for the APIs.
     - Also add command line administrator authentication.
  5. Do you already have a preferred command structure or configuration-file format?
     - I do not have a preferred command structure yet.
  6. Should the prototype target a standalone Splunk instance first, or also support distributed deployments such as search-head clusters?
     - Target a standalone Splunk instance first, distributed deployment support can come later.

## CLI usage

Authenticate using either an explicit management URL or a configured instance:

```sh
bin/cli auth login --url https://splunk01.example.com:8089
bin/cli auth login --instance splunk01
```

Validate and apply configuration or download service provider metadata:

```sh
bin/cli saml validate
bin/cli saml validate --instance splunk01 --remote
bin/cli saml configure --instance splunk01
bin/cli saml metadata --instance splunk01
```

The default configuration file is `~/.config/splunk-saml/saml.json`. Use `--config path` to select a different file, such as the repository example:

```sh
bin/cli saml validate --config examples/saml.json
```

## Instance configuration

Each entry in the root `instances` object is keyed by a short-form hostname and requires a `hostname`, which can be an FQDN or IP address. When the URLs are omitted, the CLI derives them as follows:

- `managementUrl`: `https://<hostname>:8089`
- `webUrl`: `https://<hostname>:8000`

Set either URL explicitly when Splunk uses different ports, an internal management name, or a reverse proxy. For example:

```json
{
  "instances": {
    "splunk01": {
      "hostname": "splunk01.example.com",
      "managementUrl": "https://splunk01.internal.example.com:8089",
      "webUrl": "https://splunk.example.com",
      "loadBalancerHostname": "splunk.example.com"
    }
  }
}
```

`loadBalancerHostname` is optional. When present, `saml configure` sends it as Splunk's SAML `fqdn` setting, corresponding to the **Load balancer hostname or IP address** field in Splunk Web. Leave it unset when users access a standalone instance directly.

## IdP metadata and signing certificates

Use `metadataUrl` for the normal Microsoft Entra setup. The CLI retrieves the IdP metadata before configuring Splunk, verifies that it contains an SAML `EntityDescriptor`, and validates every distinct signing certificate found in its signing `KeyDescriptor` elements. Multiple certificates are retained by the metadata flow so an Entra rollover certificate is not discarded.

The former inline `certificate` field is no longer supported. Splunk's HTTPS certificate is unrelated to SAML assertion signing, and the Entra signing certificates are already present in its metadata.

For a manually managed IdP certificate, omit `metadataUrl` and set `idpCertificatePath` instead:

```json
{
  "instances": {
    "splunk01": {
      "hostname": "splunk01.example.com",
      "idpCertificatePath": "entra/signing",
      "entityId": "https://splunk01.example.com:8000",
      "ssoUrl": "https://login.microsoftonline.com/<tenant-id>/saml2"
    }
  }
}
```

This path is on the Splunk host and maps to Splunk's `idpCertPath` setting; it is not a path on the machine running this CLI. Configure exactly one of `metadataUrl` or `idpCertificatePath`.

`saml validate` performs local schema validation. Add `--remote` to retrieve the IdP metadata and report how many signing certificates it contains without changing Splunk.

## HTTP debugging

Add `-d` or `--debug` to display outgoing HTTP requests. Add a second level with `-dd`, `-d -d`, or `--debug --debug` to display responses as well:

```sh
bin/cli saml configure --instance splunk01 -d
bin/cli saml configure --instance splunk01 -dd
```

Debug output is written to standard error. Passwords, session keys, authorization headers, tokens, and cookies are redacted.
