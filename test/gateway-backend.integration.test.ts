import { createHmac } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { loadConfig, type AppConfig } from "../src/config.js";
import {
  ArchiveBridgeClient,
  canonicalJson,
} from "../src/gateway/archive-bridge-client.js";
import {
  ARCHIVE_TOOLS,
  ARCHIVE_TOOL_NAMES,
} from "../src/gateway/archive-tools.js";
import {
  startHttpServer,
  type RunningHttpServer,
} from "../src/http-server.js";
import { createServices } from "../src/mcp-server.js";

function endpoint(running: RunningHttpServer, config: AppConfig): URL {
  const address = running.httpServer.address() as AddressInfo;
  return new URL(`http://127.0.0.1:${address.port}${config.endpoint}`);
}

async function connect(url: URL, bearer?: string): Promise<{
  client: Client;
  transport: StreamableHTTPClientTransport;
}> {
  const client = new Client({ name: "gateway-backend-test", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(url, {
    requestInit: bearer
      ? { headers: { Authorization: `Bearer ${bearer}` } }
      : undefined,
  });
  await client.connect(transport);
  return { client, transport };
}

describe("gateway and private generic backend", () => {
  let root: string;
  let backendRoot: string;
  let gatewayRoot: string;
  let exchangeRoot: string;
  let keyFile: string;
  let backendConfig: AppConfig;
  let gatewayConfig: AppConfig;
  let backend: RunningHttpServer;
  let gateway: RunningHttpServer;
  let backendUrl: URL;
  let gatewayUrl: URL;

  beforeAll(async () => {
    root = await mkdtemp(path.join(os.tmpdir(), "cokacremote-gateway-backend-test-"));
    backendRoot = path.join(root, "backend-root");
    gatewayRoot = path.join(root, "gateway-root");
    exchangeRoot = path.join(root, "bridge-exchange");
    keyFile = path.join(root, "bridge-attestation.key");
    await writeFile(keyFile, "k".repeat(64) + "\n", { mode: 0o600 });

    backendConfig = loadConfig(
      {
        MCP_MODE: "generic-backend",
        MCP_ALLOW_NO_AUTH: "true",
        MCP_OAUTH_ENABLED: "false",
        MCP_HOST: "127.0.0.1",
        MCP_DEFAULT_CWD: backendRoot,
      },
      backendRoot,
    );
    backendConfig.port = 0;
    backend = await startHttpServer(
      backendConfig,
      createServices(backendConfig),
    );
    backendUrl = endpoint(backend, backendConfig);

    gatewayConfig = loadConfig(
      {
        MCP_MODE: "gateway",
        MCP_AUTH_TOKEN: "dummy-gateway-static-value",
        MCP_OAUTH_ENABLED: "true",
        MCP_OAUTH_APPROVAL_KEY: "dummy-gateway-oauth-approval",
        MCP_PUBLIC_URL: "http://127.0.0.1:45679",
        MCP_HOST: "127.0.0.1",
        MCP_DEFAULT_CWD: gatewayRoot,
        MCP_GENERIC_BACKEND_URL: backendUrl.href,
        MCP_BRIDGE_EXCHANGE_ROOT: exchangeRoot,
        MCP_BRIDGE_ATTESTATION_KEY_FILE: keyFile,
        MCP_BRIDGE_GENERATION: "7",
        MCP_GATEWAY_SOURCE_FINGERPRINT: "a".repeat(64),
        MCP_BRIDGE_RESULT_WAIT_MS: "0",
      },
      gatewayRoot,
    );
    gatewayConfig.port = 0;
    gateway = await startHttpServer(gatewayConfig);
    gatewayUrl = endpoint(gateway, gatewayConfig);
  });

  afterAll(async () => {
    await gateway?.close();
    await backend?.close();
    await rm(root, { recursive: true, force: true });
  });

  it("preserves generic tool definitions and process semantics through the gateway", async () => {
    const backendSession = await connect(backendUrl);
    const gatewaySession = await connect(
      gatewayUrl,
      "dummy-gateway-static-value",
    );
    try {
      const backendTools = await backendSession.client.listTools();
      const gatewayTools = await gatewaySession.client.listTools();
      const backendByName = new Map(
        backendTools.tools.map((tool) => [tool.name, tool]),
      );
      const gatewayByName = new Map(
        gatewayTools.tools.map((tool) => [tool.name, tool]),
      );

      for (const [name, definition] of backendByName) {
        const gatewayDefinition = gatewayByName.get(name);
        expect(gatewayDefinition).toBeDefined();
        const { _meta: backendMeta, ...backendPublic } = definition;
        const { _meta: gatewayMeta, ...gatewayPublic } = gatewayDefinition!;
        expect(backendMeta).toBeUndefined();
        expect(gatewayPublic).toEqual(backendPublic);
        expect(gatewayMeta).toEqual({
          securitySchemes: [{ type: "oauth2", scopes: ["mcp:tools"] }],
        });
      }
      expect(gatewayTools.tools.map((tool) => tool.name)).toEqual(
        expect.arrayContaining(Object.values(ARCHIVE_TOOL_NAMES)),
      );
      for (const name of Object.values(ARCHIVE_TOOL_NAMES)) {
        expect(gatewayByName.get(name)?._meta).toEqual({
          securitySchemes: [{ type: "oauth2", scopes: ["mcp:tools"] }],
        });
      }

      const write = await gatewaySession.client.callTool({
        name: "write_file",
        arguments: {
          path: "proxied.txt",
          content: "through-private-backend\n",
        },
      });
      expect(write.isError).not.toBe(true);
      const read = await gatewaySession.client.callTool({
        name: "read_file",
        arguments: { path: "proxied.txt" },
      });
      expect(read.structuredContent).toMatchObject({
        content: "through-private-backend\n",
        eof: true,
      });

      const started = await gatewaySession.client.callTool({
        name: "exec_command",
        arguments: {
          cmd: "node -e \"setTimeout(() => console.log('proxy-session-ok'), 80)\"",
          yieldTimeMs: 0,
        },
      });
      const sessionId = (
        started.structuredContent as { sessionId?: string } | undefined
      )?.sessionId;
      expect(sessionId).toEqual(expect.any(String));
      let completed = await gatewaySession.client.callTool({
        name: "read_process",
        arguments: { sessionId, waitMs: 3000 },
      });
      let processState = completed.structuredContent as
        | {
            completed?: boolean;
            exitCode?: number | null;
            stdout?: string;
            nextSeq?: number;
          }
        | undefined;
      let observedStdout = processState?.stdout ?? "";
      if (!processState?.completed) {
        completed = await gatewaySession.client.callTool({
          name: "read_process",
          arguments: {
            sessionId,
            afterSeq: processState?.nextSeq ?? 0,
            waitMs: 3000,
          },
        });
        processState = completed.structuredContent as typeof processState;
        observedStdout += processState?.stdout ?? "";
      }
      expect(processState).toMatchObject({
        completed: true,
        exitCode: 0,
      });
      expect(observedStdout).toContain("proxy-session-ok");

      const gatewayHealth = await fetch(new URL("/health", gatewayUrl));
      expect(await gatewayHealth.json()).toMatchObject({
        status: "ok",
        mode: "gateway",
        managedProcesses: 0,
        unrestrictedHostAccess: false,
      });
      const backendHealth = await fetch(new URL("/health", backendUrl));
      expect(await backendHealth.json()).toMatchObject({
        status: "ok",
        mode: "generic-backend",
        unrestrictedHostAccess: true,
      });
    } finally {
      await gatewaySession.transport.terminateSession();
      await gatewaySession.client.close();
      await backendSession.transport.terminateSession();
      await backendSession.client.close();
    }
  });

  it("does not turn a static bearer into Archive OAuth authority", async () => {
    const session = await connect(gatewayUrl, "dummy-gateway-static-value");
    try {
      await expect(
        session.client.callTool({
          name: ARCHIVE_TOOL_NAMES.preview,
          arguments: {
            target_operation_id: "123e4567-e89b-42d3-a456-426614174000",
          },
        }),
      ).rejects.toThrow(/verified OAuth AuthInfo/);
    } finally {
      await session.transport.terminateSession();
      await session.client.close();
    }
  });

  it("publishes a closed attested bridge request without raw OAuth token material", async () => {
    const oauthBase = "http://127.0.0.1:45678";
    const config = loadConfig(
      {
        MCP_MODE: "gateway",
        MCP_OAUTH_ENABLED: "true",
        MCP_OAUTH_APPROVAL_KEY: "dummy-oauth-approval-value",
        MCP_PUBLIC_URL: oauthBase,
        MCP_GENERIC_BACKEND_URL: backendUrl.href,
        MCP_BRIDGE_EXCHANGE_ROOT: exchangeRoot,
        MCP_BRIDGE_ATTESTATION_KEY_FILE: keyFile,
        MCP_BRIDGE_GENERATION: "7",
        MCP_GATEWAY_SOURCE_FINGERPRINT: "a".repeat(64),
        MCP_BRIDGE_RESULT_WAIT_MS: "0",
      },
      gatewayRoot,
    );
    const authInfo: AuthInfo = {
      token: "dummy-raw-oauth-token-value",
      clientId: "oauth-client-1",
      scopes: ["mcp:tools", "mcp:tools"],
      expiresAt: Math.floor(Date.now() / 1000) + 240,
      resource: new URL(`${oauthBase}/mcp`),
    };
    const client = new ArchiveBridgeClient(config);
    const targetOperation = "123e4567-e89b-42d3-a456-426614174000";
    const submission = await client.submit(
      "source_draft_preview",
      { target_operation_id: targetOperation },
      authInfo,
    );
    expect(submission).toMatchObject({
      pending: true,
      automaticResubmissionAllowed: false,
    });

    const requestDirectory = path.join(exchangeRoot, "requests");
    const requestNames = (await readdir(requestDirectory)).filter((name) =>
      name.endsWith(".json"),
    );
    expect(requestNames).toHaveLength(1);
    const raw = await readFile(
      path.join(requestDirectory, requestNames[0]!),
      "utf8",
    );
    expect(raw).not.toContain("dummy-raw-oauth-token-value");
    const request = JSON.parse(raw) as Record<string, unknown>;
    expect(request).toMatchObject({
      schema_version: "aias-receiving-host-bridge-request-v1",
      bridge_generation: 7,
      gateway_source_fingerprint: "a".repeat(64),
      operation: "source_draft_preview",
      oauth: {
        client_id: "oauth-client-1",
        scopes: ["mcp:tools"],
        resource: `${oauthBase}/mcp`,
      },
      semantic_payload: {
        target_operation_id: targetOperation,
      },
    });
    expect(
      (request.semantic_payload as Record<string, unknown>).project_key,
    ).toBeUndefined();
    expect((request.oauth as Record<string, unknown>).token).toBeUndefined();

    const { mac_sha256: mac, ...unsigned } = request;
    const expectedMac = createHmac(
      "sha256",
      Buffer.from("k".repeat(64), "utf8"),
    )
      .update(canonicalJson(unsigned), "utf8")
      .digest("hex");
    expect(mac).toBe(expectedMac);
  });

  it("rejects bridge exchange paths that traverse symlinks", async () => {
    const oauthBase = "http://127.0.0.1:45679";
    const realExchange = path.join(root, "real-bridge-exchange");
    const linkedExchange = path.join(root, "linked-bridge-exchange");
    await mkdir(realExchange, { recursive: true });
    await symlink(realExchange, linkedExchange, "dir");

    const config = loadConfig(
      {
        MCP_MODE: "gateway",
        MCP_OAUTH_ENABLED: "true",
        MCP_OAUTH_APPROVAL_KEY: "dummy-oauth-approval-value",
        MCP_PUBLIC_URL: oauthBase,
        MCP_GENERIC_BACKEND_URL: backendUrl.href,
        MCP_BRIDGE_EXCHANGE_ROOT: linkedExchange,
        MCP_BRIDGE_ATTESTATION_KEY_FILE: keyFile,
        MCP_BRIDGE_GENERATION: "7",
        MCP_GATEWAY_SOURCE_FINGERPRINT: "a".repeat(64),
        MCP_BRIDGE_RESULT_WAIT_MS: "0",
      },
      gatewayRoot,
    );
    const authInfo: AuthInfo = {
      token: "dummy-raw-oauth-token-value",
      clientId: "oauth-client-1",
      scopes: ["mcp:tools"],
      expiresAt: Math.floor(Date.now() / 1000) + 240,
      resource: new URL(`${oauthBase}/mcp`),
    };

    await expect(
      new ArchiveBridgeClient(config).submit(
        "source_draft_preview",
        { target_operation_id: "123e4567-e89b-42d3-a456-426614174000" },
        authInfo,
      ),
    ).rejects.toThrow(/not a real directory|symbolic link/);
    expect(await readdir(realExchange)).toEqual([]);
  });

  it("keeps the source-only Compose privilege boundary explicit", async () => {
    const compose = await readFile(
      new URL("../tunneling/docker-compose.yml", import.meta.url),
      "utf8",
    );
    const gatewayStart = compose.indexOf("  workmachine:");
    const backendStart = compose.indexOf("  generic-backend:");
    const cloudflaredStart = compose.indexOf("  cloudflared:");
    const networksStart = compose.indexOf("\nnetworks:");
    expect(gatewayStart).toBeGreaterThanOrEqual(0);
    expect(backendStart).toBeGreaterThan(gatewayStart);
    expect(cloudflaredStart).toBeGreaterThan(backendStart);
    expect(networksStart).toBeGreaterThan(cloudflaredStart);

    const gateway = compose.slice(gatewayStart, backendStart);
    const backend = compose.slice(backendStart, cloudflaredStart);
    const networks = compose.slice(networksStart);

    expect(gateway).toContain("MCP_MODE: gateway");
    expect(gateway).toContain("cokacremote-state");
    expect(gateway).toContain("BRIDGE_EXCHANGE_PATH");
    expect(gateway).toContain("BRIDGE_ATTESTATION_KEY_PATH");
    expect(gateway).toContain("read_only: true");
    expect(gateway).not.toContain("SHARED_PATH");

    expect(backend).toContain("MCP_MODE: generic-backend");
    expect(backend).toContain('MCP_ALLOW_NO_AUTH: "true"');
    expect(backend).toContain('MCP_OAUTH_ENABLED: "false"');
    expect(backend).toContain("SHARED_PATH");
    expect(backend).not.toContain("cokacremote-state");
    expect(backend).not.toContain("BRIDGE_EXCHANGE_PATH");
    expect(backend).not.toContain("BRIDGE_ATTESTATION_KEY_PATH");
    expect(backend).not.toContain("MCP_PUBLIC_URL");
    expect(backend).not.toMatch(/^\s+ports:/m);
    expect(backend).not.toContain("- public");
    expect(networks).toContain("internal: true");

    const dockerfile = await readFile(
      new URL("../tunneling/Dockerfile", import.meta.url),
      "utf8",
    );
    expect(dockerfile).toContain('MCP_MODE=monolith');
    expect(dockerfile).toContain(
      'if [[ "${mode}" == "generic-backend" ]]; then',
    );
    expect(dockerfile).toContain("client_max_body_size 8m;");
  });

  it("keeps Archive public schemas closed to host-owned authority fields", () => {
    const byName = new Map(ARCHIVE_TOOLS.map((tool) => [tool.name, tool]));
    const preview = byName.get(ARCHIVE_TOOL_NAMES.preview)!;
    const decide = byName.get(ARCHIVE_TOOL_NAMES.decide)!;
    const forbidden = [
      "client_id",
      "client_role",
      "request_id",
      "operation_id",
      "source_fingerprint",
      "created_at",
      "nonce",
      "mac_sha256",
      "path",
      "private_root",
      "native_action",
      "task_name",
      "sid",
      "callback",
    ];

    for (const tool of ARCHIVE_TOOLS) {
      expect(tool.inputSchema.additionalProperties).toBe(false);
      const properties = Object.keys(tool.inputSchema.properties ?? {});
      for (const field of forbidden) {
        expect(properties).not.toContain(field);
      }
    }
    expect(Object.keys(preview.inputSchema.properties ?? {})).not.toContain(
      "project_key",
    );
    expect(Object.keys(decide.inputSchema.properties ?? {})).not.toContain(
      "project_key",
    );
  });
});
