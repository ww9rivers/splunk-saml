#!/usr/bin/env bun

import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";

type Credentials = {
  baseUrl: string;
  username: string;
  sessionKey: string;
  createdAt: string;
  insecure?: boolean;
};

type SAMLConfig = {
  samlStanzaName?: string;
  tenantId: string;
  metadataUrl?: string;
  idpCertificatePath?: string;
  entityId: string;
  ssoUrl: string;
  usernameAttribute?: string;
  groupAttribute: string;
  roleMapping: Record<string, string[]>;
};

type InstanceConfig = SAMLConfig & {
  hostname: string;
  managementUrl: string;
  webUrl: string;
  loadBalancerHostname?: string;
};

type ConfigFile = {
  groupAttribute: string;
  roleMapping: Record<string, string[]>;
  instances: Record<string, InstanceConfig>;
};

const DEFAULT_ROLE_MAPPING: Record<string, string[]> = { SplunkAdmins: ["admin"] };
const DEFAULT_GROUP_ATTRIBUTE = "role";

const args = process.argv.slice(2);
const debugLevel = Math.min(2, args.reduce((level, argument) => {
  if (argument === "--debug") return level + 1;
  if (/^-d+$/.test(argument)) return level + argument.length - 1;
  return level;
}, 0));
const commandArgs = args.filter((argument) => argument !== "--debug" && !/^-d+$/.test(argument));

function usage(): never {
  console.log(`splunk-saml - configure SAML authentication on a standalone Splunk instance

Usage:
  splunk-saml auth login --url https://splunk.example.com:8089 [--username admin]
  splunk-saml auth login --instance short-hostname [--config path] [--username admin]
  splunk-saml auth status [--credentials path]
  splunk-saml saml validate [--config path] [--instance short-hostname]
  splunk-saml saml configure --instance short-hostname [--config path] [--credentials path]
  splunk-saml saml metadata --instance short-hostname [--config path] [--output file]

Options:
  --config path       Configuration file (default: ~/.config/splunk-saml/saml.json)
  --credentials path  Credentials file (default: ~/.config/splunk-saml/credentials.json)
  -d, --debug         Show HTTP requests; repeat (-dd) to also show responses
  --password-stdin    Read the administrator password from standard input
  --insecure          Allow an untrusted Splunk TLS certificate (development only)
  --remote            Retrieve and validate IdP metadata during saml validate
  --force             Replace an existing metadata output file
  --help              Show this help
`);
  process.exit(0);
}

function option(name: string): string | undefined {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
}

function hasFlag(name: string): boolean {
  return args.includes(name);
}

function requiredOption(name: string): string {
  const value = option(name);
  if (!value || value.startsWith("--")) throw new Error(`Missing required option ${name}`);
  return value;
}

function credentialsPath(): string {
  return resolve(option("--credentials") ?? join(homedir(), ".config", "splunk-saml", "credentials.json"));
}

function configPath(): string {
  return resolve(option("--config") ?? join(homedir(), ".config", "splunk-saml", "saml.json"));
}

class PromptOutput extends Writable {
  muted = false;

  override _write(
    chunk: string | Uint8Array,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    if (this.muted) {
      callback();
      return;
    }
    process.stdout.write(chunk, encoding, callback);
  }
}

async function readLoginInput(): Promise<{ username: string; password: string }> {
  if (hasFlag("--password-stdin")) {
    const username = option("--username");
    if (!username) throw new Error("--password-stdin requires --username");
    return { username, password: (await Bun.stdin.text()).trimEnd() };
  }

  if (!process.stdin.isTTY) {
    throw new Error("Interactive login requires a terminal; use --username with --password-stdin for piped input");
  }

  const output = new PromptOutput();
  const terminal = createInterface({ input: process.stdin, output, terminal: true });
  try {
    const username = option("--username") ?? (await terminal.question("Splunk administrator username: ")).trim();
    process.stdout.write("Splunk administrator password: ");
    output.muted = true;
    const password = await terminal.question("");
    output.muted = false;
    process.stdout.write("\n");
    return { username, password };
  } finally {
    output.muted = false;
    terminal.close();
  }
}

async function readCredentials(): Promise<Credentials> {
  const value = JSON.parse(await readFile(credentialsPath(), "utf8")) as Credentials;
  if (!value.baseUrl || !value.sessionKey) throw new Error(`Invalid credentials file: ${credentialsPath()}`);
  return value;
}

async function saveCredentials(value: Credentials): Promise<void> {
  const path = credentialsPath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

function apiUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/$/, "")}${path}`;
}

function isSensitiveName(name: string): boolean {
  const normalized = name.replace(/[-_]/g, "");
  return /(authorization|cookie|password|passwd|secret|token|sessionkey|apikey)/i.test(normalized);
}

function redact(value: unknown, key = ""): unknown {
  if (isSensitiveName(key)) return "[REDACTED]";
  if (Array.isArray(value)) return value.map((item) => redact(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entryValue]) => [entryKey, redact(entryValue, entryKey)]),
    );
  }
  return value;
}

function debugUrl(url: string): string {
  try {
    const parsed = new URL(url);
    for (const key of parsed.searchParams.keys()) {
      if (isSensitiveName(key)) parsed.searchParams.set(key, "[REDACTED]");
    }
    return parsed.toString();
  } catch {
    return url;
  }
}

function debugHeaders(headers?: HeadersInit): Record<string, string> {
  const entries: Record<string, string> = {};
  for (const [key, value] of new Headers(headers).entries()) {
    entries[key] = isSensitiveName(key) ? "[REDACTED]" : value;
  }
  return entries;
}

function redactText(text: string): unknown {
  try {
    return redact(JSON.parse(text));
  } catch {
    return text
      .replace(/(<(?:sessionKey|token)>)[\s\S]*?(<\/(?:sessionKey|token)>)/gi, "$1[REDACTED]$2")
      .replace(/((?:sessionKey|token|password)=)[^&\s]+/gi, "$1[REDACTED]");
  }
}

function debugBody(body: BodyInit | null | undefined): unknown {
  if (body === undefined || body === null) return undefined;
  if (body instanceof URLSearchParams) {
    return redact(Object.fromEntries(body.entries()));
  }
  if (typeof body === "string") return redactText(body);
  return `[${body.constructor?.name ?? "Body"}]`;
}

function logRequest(url: string, init: RequestInit): void {
  if (debugLevel < 1) return;
  const request = {
    method: init.method ?? "GET",
    url: debugUrl(url),
    headers: debugHeaders(init.headers),
    ...(init.body === undefined || init.body === null ? {} : { body: debugBody(init.body) }),
  };
  console.error(`[debug] HTTP request\n${JSON.stringify(request, null, 2)}`);
}

async function logResponse(url: string, response: Response): Promise<void> {
  if (debugLevel < 2) return;
  let body: unknown;
  try {
    body = redactText(await response.clone().text());
  } catch (error) {
    body = `[Unable to read response body: ${error instanceof Error ? error.message : String(error)}]`;
  }
  const details = {
    url: debugUrl(url),
    status: response.status,
    statusText: response.statusText,
    headers: debugHeaders(response.headers),
    body,
  };
  console.error(`[debug] HTTP response\n${JSON.stringify(details, null, 2)}`);
}

async function httpFetch(url: string, init: RequestInit = {}): Promise<Response> {
  logRequest(url, init);
  try {
    const response = await fetch(url, init);
    await logResponse(url, response);
    return response;
  } catch (error) {
    if (debugLevel > 0) {
      console.error(`[debug] HTTP request failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    throw error;
  }
}

async function splunkFetch(url: string, init: RequestInit, insecure = false): Promise<Response> {
  const request = insecure
    ? { ...init, tls: { rejectUnauthorized: false } }
    : init;
  try {
    return await httpFetch(url, request as RequestInit);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    const tlsHint = url.startsWith("https://") && !insecure
      ? " If this standalone instance uses a self-signed certificate, retry with --insecure."
      : "";
    throw new Error(`Unable to connect to Splunk at ${url}: ${reason}${tlsHint}`);
  }
}

async function login(): Promise<void> {
  const explicitUrl = hasFlag("--url") ? requiredOption("--url") : undefined;
  const instance = explicitUrl ? undefined : await loadInstance();
  const baseUrl = (explicitUrl ?? instance?.config.managementUrl)?.replace(/\/$/, "");
  if (!baseUrl) {
    throw new Error("Provide --url, or provide --config and --instance to use an instance management URL");
  }
  const insecure = hasFlag("--insecure");
  const { username, password } = await readLoginInput();
  if (!username) throw new Error("Administrator username cannot be empty");
  if (!password) throw new Error("Administrator password cannot be empty");

  const body = new URLSearchParams({ username, password, output_mode: "json" });
  const response = await splunkFetch(apiUrl(baseUrl, "/services/auth/login"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  }, insecure);
  const text = await response.text();
  if (!response.ok) throw new Error(`Splunk login failed (${response.status}): ${text}`);
  const parsed = JSON.parse(text) as { sessionKey?: string; entry?: Array<{ content?: { sessionKey?: string } }> };
  const sessionKey = parsed.sessionKey ?? parsed.entry?.[0]?.content?.sessionKey;
  if (!sessionKey) throw new Error("Splunk login succeeded but no session key was returned");
  await saveCredentials({ baseUrl, username, sessionKey, createdAt: new Date().toISOString(), insecure });
  console.log(`Authenticated as ${username}. Credentials saved to ${credentialsPath()}`);
}

async function status(): Promise<void> {
  const credentials = await readCredentials();
  const response = await splunkFetch(apiUrl(credentials.baseUrl, "/services/server/info?output_mode=json"), {
    headers: { Authorization: `Splunk ${credentials.sessionKey}` },
  }, credentials.insecure);
  if (!response.ok) throw new Error(`Splunk status request failed (${response.status})`);
  const parsed = await response.json() as { entry?: Array<{ content?: { version?: string; build?: string } }> };
  const info = parsed.entry?.[0]?.content ?? {};
  console.log(JSON.stringify({ username: credentials.username, version: info.version, build: info.build }, null, 2));
}

function normalizeHostname(instanceName: string, field: string, value: unknown): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Instance "${instanceName}" is missing: ${field}`);
  }

  const candidate = value.trim();
  try {
    const url = new URL(`https://${candidate}`);
    if (
      url.username || url.password || url.port || url.pathname !== "/" ||
      url.search || url.hash || url.host.toLowerCase() !== candidate.toLowerCase()
    ) {
      throw new Error();
    }
  } catch {
    throw new Error(`Instance "${instanceName}" has an invalid ${field}; use a hostname or IP address without a scheme, port, or path`);
  }
  return candidate;
}

function validateUrl(instanceName: string, field: string, value: unknown): string {
  if (typeof value !== "string" || !value) {
    throw new Error(`Instance "${instanceName}" is missing: ${field}`);
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error();
    return url.toString().replace(/\/$/, "");
  } catch {
    throw new Error(`Instance "${instanceName}" has an invalid ${field}`);
  }
}

function substituteTenantId(instanceName: string, field: string, value: string, tenantId: string): string {
  const substituted = value.replaceAll("<tenantId>", tenantId);
  const unresolved = substituted.match(/<[^<>]+>/)?.[0];
  if (unresolved) {
    throw new Error(
      `Instance "${instanceName}" has an unresolved placeholder ${unresolved} in ${field}; only <tenantId> is substituted automatically`,
    );
  }
  return substituted;
}

function resolveRoleMapping(context: string, value: unknown, fallback: Record<string, string[]>): Record<string, string[]> {
  if (value === undefined) return fallback;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${context} has an invalid roleMapping`);
  }

  const normalized: Record<string, string[]> = {};
  for (const [group, configuredRoles] of Object.entries(value)) {
    if (!group.trim()) throw new Error(`${context} has an empty SAML group in roleMapping`);
    const roles = typeof configuredRoles === "string" ? [configuredRoles] : configuredRoles;
    if (
      !Array.isArray(roles) || !roles.length ||
      roles.some((role) => typeof role !== "string" || !role.trim())
    ) {
      throw new Error(`${context} has invalid Splunk roles for SAML group "${group}"`);
    }
    normalized[group] = [...new Set(roles.map((role) => role.trim()))];
  }
  return normalized;
}

function extractSigningCertificates(metadata: string): string[] {
  const certificates = new Set<string>();
  const keyDescriptors = metadata.matchAll(
    /<(?:[A-Za-z0-9_.-]+:)?KeyDescriptor\b([^>]*)>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?KeyDescriptor\s*>/gi,
  );

  for (const descriptor of keyDescriptors) {
    const attributes = descriptor[1] ?? "";
    const use = attributes.match(/\buse\s*=\s*(["'])(.*?)\1/i)?.[2]?.toLowerCase();
    if (use && use !== "signing") continue;

    const certificateElements = (descriptor[2] ?? "").matchAll(
      /<(?:[A-Za-z0-9_.-]+:)?X509Certificate\b[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?X509Certificate\s*>/gi,
    );
    for (const element of certificateElements) {
      const certificate = (element[1] ?? "").replace(/\s/g, "");
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(certificate) || certificate.length < 64) {
        throw new Error("IdP metadata contains an invalid signing certificate");
      }
      certificates.add(certificate);
    }
  }
  return [...certificates];
}

async function fetchIdpMetadata(instanceName: string, metadataUrl: string): Promise<{ xml: string; certificates: string[] }> {
  let response: Response;
  try {
    response = await httpFetch(metadataUrl, {
      headers: { Accept: "application/samlmetadata+xml, application/xml, text/xml" },
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to retrieve IdP metadata for "${instanceName}" from ${metadataUrl}: ${reason}`);
  }

  const xml = await response.text();
  if (!response.ok) {
    throw new Error(`IdP metadata request for "${instanceName}" failed (${response.status}): ${xml}`);
  }
  if (!/<(?:[A-Za-z0-9_.-]+:)?EntityDescriptor(?:\s|>)/.test(xml)) {
    throw new Error(`IdP metadata for "${instanceName}" does not contain an EntityDescriptor`);
  }

  const certificates = extractSigningCertificates(xml);
  if (!certificates.length) {
    throw new Error(`IdP metadata for "${instanceName}" does not contain a signing certificate`);
  }
  return { xml, certificates };
}

function resolveInstance(
  name: string,
  value: unknown,
  sharedGroupAttribute: string,
  sharedRoleMapping: Record<string, string[]>,
): InstanceConfig {
  if (!/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(name)) {
    throw new Error(`Invalid instance key "${name}": use a short-form hostname without dots`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Instance "${name}" must be a JSON object`);
  }

  const instance = value as Record<string, unknown>;
  const required = ["hostname", "tenantId", "entityId", "ssoUrl"];
  const missing = required.filter((key) => typeof instance[key] !== "string" || !instance[key]);
  if (missing.length) throw new Error(`Instance "${name}" is missing: ${missing.join(", ")}`);

  const tenantId = String(instance.tenantId).trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId)) {
    throw new Error(`Instance "${name}" has an invalid tenantId; use the Microsoft Entra Directory (tenant) ID`);
  }

  if ("certificate" in instance) {
    throw new Error(`Instance "${name}" uses the retired certificate field; remove it and use metadataUrl or idpCertificatePath`);
  }
  const hasMetadataUrl = typeof instance.metadataUrl === "string" && Boolean(instance.metadataUrl);
  const hasCertificatePath = typeof instance.idpCertificatePath === "string" && Boolean(instance.idpCertificatePath);
  if (hasMetadataUrl === hasCertificatePath) {
    throw new Error(`Instance "${name}" must set exactly one of metadataUrl or idpCertificatePath`);
  }

  const hostname = normalizeHostname(name, "hostname", instance.hostname);
  const loadBalancerHostname = instance.loadBalancerHostname === undefined
    ? undefined
    : normalizeHostname(name, "loadBalancerHostname", instance.loadBalancerHostname);
  const managementUrl = validateUrl(
    name,
    "managementUrl",
    instance.managementUrl ?? `https://${hostname}:8089`,
  );
  const webUrl = validateUrl(name, "webUrl", instance.webUrl ?? `https://${hostname}:8000`);
  const metadataUrl = hasMetadataUrl
    ? validateUrl(
      name,
      "metadataUrl",
      substituteTenantId(name, "metadataUrl", String(instance.metadataUrl), tenantId),
    )
    : undefined;
  const ssoUrl = validateUrl(
    name,
    "ssoUrl",
    substituteTenantId(name, "ssoUrl", String(instance.ssoUrl), tenantId),
  );

  if (instance.managementUrl !== undefined && typeof instance.managementUrl !== "string") {
    throw new Error(`Instance "${name}" has an invalid managementUrl`);
  }
  if (instance.webUrl !== undefined && typeof instance.webUrl !== "string") {
    throw new Error(`Instance "${name}" has an invalid webUrl`);
  }

  for (const field of ["samlStanzaName", "usernameAttribute", "groupAttribute"]) {
    if (instance[field] !== undefined && typeof instance[field] !== "string") {
      throw new Error(`Instance "${name}" has an invalid ${field}`);
    }
  }
  if (typeof instance.samlStanzaName === "string" && !instance.samlStanzaName.trim()) {
    throw new Error(`Instance "${name}" has an invalid samlStanzaName`);
  }
  const groupAttribute = typeof instance.groupAttribute === "string"
    ? instance.groupAttribute.trim()
    : sharedGroupAttribute;
  if (!groupAttribute) throw new Error(`Instance "${name}" has an invalid groupAttribute`);
  const privateRoleMapping = resolveRoleMapping(`Instance "${name}"`, instance.roleMapping, {});
  const roleMapping = { ...sharedRoleMapping, ...privateRoleMapping };

  return {
    hostname,
    managementUrl,
    webUrl,
    tenantId,
    entityId: String(instance.entityId),
    ssoUrl,
    ...(typeof instance.samlStanzaName === "string" ? { samlStanzaName: instance.samlStanzaName.trim() } : {}),
    ...(metadataUrl ? { metadataUrl } : {}),
    ...(hasCertificatePath ? { idpCertificatePath: String(instance.idpCertificatePath) } : {}),
    ...(typeof instance.usernameAttribute === "string" ? { usernameAttribute: instance.usernameAttribute } : {}),
    groupAttribute,
    roleMapping,
    ...(loadBalancerHostname ? { loadBalancerHostname } : {}),
  };
}

async function loadConfigFile(): Promise<ConfigFile> {
  const path = configPath();
  const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Invalid SAML config file: ${path}`);
  }

  const root = parsed as { groupAttribute?: unknown; roleMapping?: unknown; instances?: unknown };
  if (root.groupAttribute !== undefined && typeof root.groupAttribute !== "string") {
    throw new Error("Root configuration has an invalid groupAttribute");
  }
  const groupAttribute = typeof root.groupAttribute === "string"
    ? root.groupAttribute.trim()
    : DEFAULT_GROUP_ATTRIBUTE;
  if (!groupAttribute) throw new Error("Root configuration has an invalid groupAttribute");
  const roleMapping = resolveRoleMapping("Root configuration", root.roleMapping, DEFAULT_ROLE_MAPPING);
  const instances = root.instances;
  if (!instances || typeof instances !== "object" || Array.isArray(instances)) {
    throw new Error('SAML config must contain a root "instances" object');
  }

  const entries = Object.entries(instances);
  if (!entries.length) throw new Error("SAML config must contain at least one instance");
  const resolvedInstances = Object.fromEntries(
    entries.map(([name, instance]) => [name, resolveInstance(name, instance, groupAttribute, roleMapping)]),
  );
  return { groupAttribute, roleMapping, instances: resolvedInstances };
}

async function loadInstance(): Promise<{ name: string; config: InstanceConfig }> {
  const configFile = await loadConfigFile();
  const name = requiredOption("--instance");
  const config = configFile.instances[name];
  if (!config) {
    throw new Error(`Unknown instance "${name}". Available instances: ${Object.keys(configFile.instances).join(", ")}`);
  }
  return { name, config };
}

async function validateConfig(): Promise<void> {
  const configFile = await loadConfigFile();
  const selected = option("--instance");
  if (selected && !configFile.instances[selected]) {
    throw new Error(`Unknown instance "${selected}". Available instances: ${Object.keys(configFile.instances).join(", ")}`);
  }
  const count = selected ? 1 : Object.keys(configFile.instances).length;
  console.log(`SAML configuration is valid for ${count} instance${count === 1 ? "" : "s"}.`);

  if (hasFlag("--remote")) {
    const entries = selected
      ? [[selected, configFile.instances[selected]] as const]
      : Object.entries(configFile.instances);
    await Promise.all(entries.map(async ([name, config]) => {
      if (!config.metadataUrl) {
        console.log(`Instance "${name}" uses manually managed IdP certificate path ${config.idpCertificatePath}.`);
        return;
      }
      const metadata = await fetchIdpMetadata(name, config.metadataUrl);
      console.log(`IdP metadata for "${name}" contains ${metadata.certificates.length} signing certificate${metadata.certificates.length === 1 ? "" : "s"}.`);
    }));
  }
}

function samlSettings(instance: InstanceConfig, idpMetadata?: string): Record<string, string> {
  const webUrl = new URL(instance.webUrl);
  const publicHostname = instance.loadBalancerHostname ?? webUrl.hostname;
  const fqdn = `${webUrl.protocol}//${publicHostname}`;
  const redirectPort = webUrl.port || (webUrl.protocol === "https:" ? "443" : "80");
  return {
    entityId: instance.entityId,
    idpSSOUrl: instance.ssoUrl,
    ...(instance.usernameAttribute ? { attributeAliasMail: instance.usernameAttribute } : {}),
    attributeAliasRole: instance.groupAttribute,
    fqdn,
    redirectPort,
    redirectAfterLogoutToUrl: `${fqdn}:${redirectPort}`,
    ...(instance.idpCertificatePath ? { idpCertPath: instance.idpCertificatePath } : {}),
    ...(idpMetadata ? { idpMetadataPayload: idpMetadata } : {}),
  };
}

function formRequest(body: URLSearchParams, sessionKey: string): RequestInit {
  return {
    method: "POST",
    headers: {
      Authorization: `Splunk ${sessionKey}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  };
}

async function configureRoleMappings(credentials: Credentials, roleMapping: Record<string, string[]>): Promise<void> {
  const collectionPath = "/services/admin/SAML-groups";
  const listResponse = await splunkFetch(apiUrl(credentials.baseUrl, `${collectionPath}?output_mode=json`), {
    headers: { Authorization: `Splunk ${credentials.sessionKey}`, Accept: "application/json" },
  }, credentials.insecure);
  const listText = await listResponse.text();
  if (!listResponse.ok) {
    throw new Error(`Unable to read existing SAML role mappings (${listResponse.status}): ${listText}`);
  }
  const parsed = JSON.parse(listText) as {
    entry?: Array<{ name?: string; content?: { roles?: string[] | string } }>;
  };
  const existing = new Map((parsed.entry ?? []).flatMap((entry) => {
    if (!entry.name) return [];
    const roles = Array.isArray(entry.content?.roles)
      ? entry.content.roles
      : typeof entry.content?.roles === "string" ? [entry.content.roles] : [];
    return [[entry.name, roles] as const];
  }));

  for (const [externalGroup, roles] of Object.entries(roleMapping)) {
    const currentRoles = existing.get(externalGroup);
    if (currentRoles && [...currentRoles].sort().join("\0") === [...roles].sort().join("\0")) continue;
    if (currentRoles) {
      const deleteResponse = await splunkFetch(
        apiUrl(credentials.baseUrl, `${collectionPath}/${encodeURIComponent(externalGroup)}`),
        { method: "DELETE", headers: { Authorization: `Splunk ${credentials.sessionKey}` } },
        credentials.insecure,
      );
      const deleteText = await deleteResponse.text();
      if (!deleteResponse.ok) {
        throw new Error(`Unable to replace SAML role mapping for "${externalGroup}" (${deleteResponse.status}): ${deleteText}`);
      }
    }

    const body = new URLSearchParams({ name: externalGroup });
    for (const role of roles) body.append("roles", role);
    const response = await splunkFetch(
      apiUrl(credentials.baseUrl, collectionPath),
      formRequest(body, credentials.sessionKey),
      credentials.insecure,
    );
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`SAML role mapping for "${externalGroup}" failed (${response.status}): ${text}`);
    }
  }
}

async function configure(): Promise<void> {
  const credentials = await readCredentials();
  const { name, config } = await loadInstance();
  if (config.managementUrl.replace(/\/$/, "") !== credentials.baseUrl.replace(/\/$/, "")) {
    throw new Error(`Credentials are for ${credentials.baseUrl}, but instance "${name}" uses ${config.managementUrl}`);
  }
  let idpMetadata: string | undefined;
  if (config.metadataUrl) {
    const metadata = await fetchIdpMetadata(name, config.metadataUrl);
    idpMetadata = metadata.xml;
    console.log(`Validated ${metadata.certificates.length} IdP signing certificate${metadata.certificates.length === 1 ? "" : "s"} from metadata.`);
  }

  const collectionPath = "/services/authentication/providers/SAML";
  const stanzaName = config.samlStanzaName ?? "saml";
  const stanzaPath = `${collectionPath}/${encodeURIComponent(stanzaName)}`;
  const lookup = await splunkFetch(apiUrl(credentials.baseUrl, `${stanzaPath}?output_mode=json`), {
    headers: { Authorization: `Splunk ${credentials.sessionKey}`, Accept: "application/json" },
  }, credentials.insecure);
  if (!lookup.ok && lookup.status !== 404) {
    throw new Error(`Unable to check SAML stanza "${stanzaName}" (${lookup.status}): ${await lookup.text()}`);
  }

  const exists = lookup.ok;
  const body = new URLSearchParams(samlSettings(config, idpMetadata));
  if (!exists) body.set("name", stanzaName);
  const response = await splunkFetch(
    apiUrl(credentials.baseUrl, exists ? stanzaPath : collectionPath),
    formRequest(body, credentials.sessionKey),
    credentials.insecure,
  );
  const text = await response.text();
  if (!response.ok) throw new Error(`SAML configuration failed (${response.status}): ${text}`);
  console.log(`SAML configuration stanza "${stanzaName}" for "${name}" ${exists ? "updated" : "created"}.`);

  if (Object.keys(config.roleMapping).length) {
    await configureRoleMappings(credentials, config.roleMapping);
    console.log(`Configured ${Object.keys(config.roleMapping).length} SAML role mapping${Object.keys(config.roleMapping).length === 1 ? "" : "s"}.`);
  }
}

async function downloadMetadata(): Promise<void> {
  const { name, config } = await loadInstance();
  const url = new URL("/saml/spmetadata", config.webUrl).toString();
  const response = await splunkFetch(url, {
    headers: { Accept: "application/samlmetadata+xml, application/xml, text/xml" },
  }, hasFlag("--insecure"));
  const metadata = await response.text();
  if (!response.ok) throw new Error(`SAML metadata download failed (${response.status}): ${metadata}`);
  if (!/<(?:[A-Za-z0-9_-]+:)?EntityDescriptor(?:\s|>)/.test(metadata)) {
    throw new Error(`Splunk at ${url} did not return SAML service provider metadata`);
  }

  const output = resolve(option("--output") ?? `${name}-sp-metadata.xml`);
  try {
    await writeFile(output, metadata, { flag: hasFlag("--force") ? "w" : "wx" });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "EEXIST") {
      throw new Error(`Output file already exists: ${output}. Use --force to replace it`);
    }
    throw error;
  }
  console.log(`SAML service provider metadata for "${name}" saved to ${output}`);
}

async function main(): Promise<void> {
  if (args.includes("--help") || args.length === 0) usage();
  const command = commandArgs.slice(0, 2).join(" ");
  if (command === "auth login") return login();
  if (command === "auth status") return status();
  if (command === "saml validate") return validateConfig();
  if (command === "saml configure") return configure();
  if (command === "saml metadata") return downloadMetadata();
  throw new Error(`Unknown command: ${command}`);
}

if (import.meta.main) {
  main().catch((error: unknown) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
