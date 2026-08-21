import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

type CapturedRequest = {
  method: string;
  path: string;
  contentType: string | null;
  body: string;
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function runConfigure(
  stanzaExists: boolean,
  options: {
    sharedGroupAttribute?: string;
    instanceGroupAttribute?: string;
    sharedRoleMapping?: Record<string, string | string[]>;
    instanceRoleMapping?: Record<string, string | string[]>;
    existingRoleMapping?: Record<string, string[]>;
  } = {},
): Promise<{ requests: CapturedRequest[]; stdout: string }> {
  const requests: CapturedRequest[] = [];
  const tenantId = "11111111-2222-4333-8444-555555555555";
  const metadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><md:IDPSSODescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${"A".repeat(64)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>`;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const body = await request.text();
      requests.push({
        method: request.method,
        path: `${url.pathname}${url.search}`,
        contentType: request.headers.get("content-type"),
        body,
      });
      if (url.pathname.endsWith("/idp-metadata")) return new Response(metadata);
      if (request.method === "GET" && url.pathname === "/services/admin/SAML-groups") {
        return Response.json({
          entry: Object.entries(options.existingRoleMapping ?? {}).map(([name, roles]) => ({ name, content: { roles } })),
        });
      }
      if (request.method === "GET" && url.pathname.endsWith("/SAML/saml")) {
        return stanzaExists ? Response.json({ entry: [{ name: "saml" }] }) : new Response("not found", { status: 404 });
      }
      if (request.method === "DELETE" && url.pathname.startsWith("/services/admin/SAML-groups/")) {
        return new Response("");
      }
      if (request.method === "POST" && url.pathname.startsWith("/services/authentication/providers/SAML")) {
        return new Response("mock SAML response body", { status: stanzaExists ? 200 : 201 });
      }
      if (request.method === "POST") return new Response("", { status: stanzaExists ? 200 : 201 });
      return new Response("unexpected request", { status: 500 });
    },
  });

  try {
    const directory = await mkdtemp(join(tmpdir(), "splunk-saml-test-"));
    temporaryDirectories.push(directory);
    const baseUrl = `http://127.0.0.1:${server.port}`;
    const configPath = join(directory, "saml.json");
    const credentialsPath = join(directory, "credentials.json");
    await writeFile(configPath, JSON.stringify({
      ...(options.sharedGroupAttribute === undefined ? {} : { groupAttribute: options.sharedGroupAttribute }),
      ...(options.sharedRoleMapping === undefined ? {} : { roleMapping: options.sharedRoleMapping }),
      instances: {
        dev4: {
          hostname: "dev4.example.com",
          tenantId,
          managementUrl: baseUrl,
          metadataUrl: `${baseUrl}/<tenantId>/idp-metadata`,
          entityId: "https://dev4.example.com:8000",
          ssoUrl: "https://login.microsoftonline.com/<tenantId>/saml2",
          ...(options.instanceGroupAttribute === undefined ? {} : { groupAttribute: options.instanceGroupAttribute }),
          ...(options.instanceRoleMapping === undefined ? {} : { roleMapping: options.instanceRoleMapping }),
        },
      },
    }));
    await writeFile(credentialsPath, JSON.stringify({
      baseUrl,
      username: "admin",
      sessionKey: "test-session-key",
      createdAt: new Date(0).toISOString(),
    }));

    const process = Bun.spawn([
      "bun",
      "run",
      "src/cli.ts",
      "saml",
      "configure",
      "--instance",
      "dev4",
      "--config",
      configPath,
      "--credentials",
      credentialsPath,
    ], {
      cwd: import.meta.dir.replace(/\/tests$/, ""),
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(process.stdout).text(),
      new Response(process.stderr).text(),
      process.exited,
    ]);
    expect(stderr).toBe("");
    expect(exitCode).toBe(0);
    return { requests, stdout };
  } finally {
    server.stop(true);
  }
}

describe("saml configure", () => {
  test("creates a missing stanza with the required name and Splunk field names", async () => {
    const { requests, stdout } = await runConfigure(false, {
      sharedGroupAttribute: "entraRole",
      sharedRoleMapping: { SplunkUsers: ["user"], MedicalSplunkAdmins: ["user"] },
      instanceRoleMapping: { MedicalSplunkAdmins: ["admin", "power"] },
    });
    const post = requests.find((request) => request.method === "POST");
    expect(post?.path).toBe("/services/authentication/providers/SAML");
    expect(post?.contentType).toStartWith("application/x-www-form-urlencoded");
    const form = new URLSearchParams(post?.body);
    expect(form.get("name")).toBe("saml");
    expect(form.get("entityId")).toBe("https://dev4.example.com:8000");
    expect(form.get("idpSSOUrl")).toBe("https://login.microsoftonline.com/11111111-2222-4333-8444-555555555555/saml2");
    expect(form.get("fqdn")).toBe("https://dev4.example.com");
    expect(form.get("redirectPort")).toBe("8000");
    expect(form.get("redirectAfterLogoutToUrl")).toBe("https://dev4.example.com:8000");
    expect(form.get("attributeAliasRole")).toBe("entraRole");
    expect(form.get("idpMetadataPayload")).toContain("<md:EntityDescriptor");
    expect(form.has("ssoUrl")).toBe(false);
    expect(form.has("metadataUrl")).toBe(false);
    expect(requests.some((request) => request.path === "/11111111-2222-4333-8444-555555555555/idp-metadata")).toBe(true);
    const roleMappingPosts = requests.filter((request) => request.path === "/services/admin/SAML-groups");
    const roleMappingPost = roleMappingPosts.find((request) => (
      new URLSearchParams(request.body).get("name") === "MedicalSplunkAdmins"
    ));
    expect(new URLSearchParams(roleMappingPost?.body).get("name")).toBe("MedicalSplunkAdmins");
    expect(new URLSearchParams(roleMappingPost?.body).getAll("roles")).toEqual(["admin", "power"]);
    const sharedMappingPost = roleMappingPosts.find((request) => (
      new URLSearchParams(request.body).get("name") === "SplunkUsers"
    ));
    expect(new URLSearchParams(sharedMappingPost?.body).getAll("roles")).toEqual(["user"]);
    expect(stdout).toContain('stanza "saml" for "dev4" created');
    expect(stdout).not.toContain("mock SAML response body");
    expect(stdout).not.toContain("[debug]");
  });

  test("updates an existing stanza through its named endpoint", async () => {
    const { requests, stdout } = await runConfigure(true);
    const post = requests.find((request) => request.method === "POST");
    expect(post?.path).toBe("/services/authentication/providers/SAML/saml");
    const form = new URLSearchParams(post?.body);
    expect(form.has("name")).toBe(false);
    expect(form.get("attributeAliasRole")).toBe("role");
    const roleMappingPost = requests.find((request) => request.path === "/services/admin/SAML-groups");
    expect(new URLSearchParams(roleMappingPost?.body).get("name")).toBe("SplunkAdmins");
    expect(new URLSearchParams(roleMappingPost?.body).getAll("roles")).toEqual(["admin"]);
    expect(stdout).toContain('stanza "saml" for "dev4" updated');
  });

  test("replaces a configured group's role mapping when its roles change", async () => {
    const { requests } = await runConfigure(
      true,
      {
        instanceRoleMapping: { SplunkAdmins: ["admin"] },
        existingRoleMapping: { SplunkAdmins: ["user"] },
      },
    );
    expect(requests.some((request) => (
      request.method === "DELETE" && request.path === "/services/admin/SAML-groups/SplunkAdmins"
    ))).toBe(true);
    const roleMappingPost = requests.find((request) => (
      request.method === "POST" && request.path === "/services/admin/SAML-groups"
    ));
    expect(new URLSearchParams(roleMappingPost?.body).getAll("roles")).toEqual(["admin"]);
  });
});
