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

The CLI creates or updates Splunk's standard `saml` configuration stanza. Set `samlStanzaName` only when the instance uses a different stanza name:

```json
"samlStanzaName": "saml-test"
```

Each instance also requires `tenantId`, set to its Microsoft Entra **Directory (tenant) ID**. The CLI substitutes the exact, case-sensitive `<tenantId>` placeholder in `metadataUrl` and `ssoUrl` before validating or using those URLs:

```json
{
  "tenantId": "11111111-2222-4333-8444-555555555555",
  "metadataUrl": "https://login.microsoftonline.com/<tenantId>/federationmetadata/2007-06/federationmetadata.xml?appid=<application-id>",
  "ssoUrl": "https://login.microsoftonline.com/<tenantId>/saml2"
}
```

Replace `<application-id>` yourself with the Entra application/client ID. The CLI rejects unresolved URL placeholders instead of sending them to Splunk.

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

For SAML, the CLI explicitly derives these Splunk settings from `webUrl`:

- `fqdn` (**Load balancer hostname or IP address**): the public scheme and FQDN without a port, such as `https://splunk01.example.com`
- `redirectPort` (**Redirect port - load balancer port**): the public web port, such as `8000`
- `redirectAfterLogoutToUrl` (**Redirect to URL after logout**): the public URL with its explicit port, such as `https://splunk01.example.com:8000`

These settings make Splunk generate an FQDN-based assertion consumer service URL, such as `https://splunk01.example.com:8000/saml/acs`, which must match the Reply URL configured in Entra. `loadBalancerHostname` is optional and overrides the hostname derived from `webUrl`; its value remains a hostname or IP address without a scheme or port.

## IdP metadata and signing certificates

Use `metadataUrl` for the normal Microsoft Entra setup. The CLI retrieves the IdP metadata before configuring Splunk, verifies that it contains an SAML `EntityDescriptor`, and validates every distinct signing certificate found in its signing `KeyDescriptor` elements. Multiple certificates are retained by the metadata flow so an Entra rollover certificate is not discarded.

The former inline `certificate` field is no longer supported. Splunk's HTTPS certificate is unrelated to SAML assertion signing, and the Entra signing certificates are already present in its metadata.

For a manually managed IdP certificate, omit `metadataUrl` and set `idpCertificatePath` instead:

```json
{
  "instances": {
    "splunk01": {
      "hostname": "splunk01.example.com",
      "tenantId": "11111111-2222-4333-8444-555555555555",
      "idpCertificatePath": "entra/signing",
      "entityId": "https://splunk01.example.com:8000",
      "ssoUrl": "https://login.microsoftonline.com/<tenantId>/saml2"
    }
  }
}
```

This path is on the Splunk host and maps to Splunk's `idpCertPath` setting; it is not a path on the machine running this CLI. Configure exactly one of `metadataUrl` or `idpCertificatePath`.

`saml validate` performs local schema validation. Add `--remote` to retrieve the IdP metadata and report how many signing certificates it contains without changing Splunk.

During `saml configure`, the CLI sends the downloaded XML as Splunk's `idpMetadataPayload`, allowing Splunk to import the IdP endpoints and signing certificates. REST requests use URL-encoded form fields, as required by the [Splunk Enterprise 10.4 access endpoint reference](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.4/access-endpoints/access-endpoint-descriptions). If the configured stanza exists it is updated through `/services/authentication/providers/SAML/<stanza>`; otherwise it is created through the collection endpoint with the required `name` field.

## SAML group role mapping

Use a root-level `roleMapping` to define mappings shared by every instance. Each group value received from Entra maps to one or more Splunk roles:

```json
{
  "roleMapping": {
    "SplunkAdmins": ["admin"],
    "SplunkUsers": ["user"]
  },
  "instances": {
    "dev4": {
      "roleMapping": {
        "SplunkAdmins": ["admin", "user"],
        "SplunkPowerUsers": ["power", "user"]
      }
    }
  }
}
```

An instance's private `roleMapping` is merged over the root mapping. A matching group replaces the shared role list for that instance; a new group extends it. When the root `roleMapping` is omitted, it defaults to `{ "SplunkAdmins": ["admin"] }`. Set the root mapping to `{}` to disable shared mappings. A single role can also be written as a string for compatibility, for example `"SplunkAdmins": "admin"`.

The CLI applies the effective per-instance mappings through Splunk's `/services/admin/SAML-groups` endpoint and replaces a listed group's existing mapping when its configured roles change. Existing Splunk groups not present in the effective mapping are left unchanged.

## HTTP debugging

Add `-d` or `--debug` to display outgoing HTTP requests. Add a second level with `-dd`, `-d -d`, or `--debug --debug` to display responses as well:

```sh
bin/cli saml configure --instance splunk01 -d
bin/cli saml configure --instance splunk01 -dd
```

Debug output is written to standard error. Passwords, session keys, authorization headers, tokens, and cookies are redacted.
