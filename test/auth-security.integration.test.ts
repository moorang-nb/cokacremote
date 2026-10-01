import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";

import express from "express";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { describe, expect, it } from "vitest";

import { createBearerAuth } from "../src/auth.js";
import { loadConfig } from "../src/config.js";
import { startHttpServer } from "../src/http-server.js";
import { createServices } from "../src/mcp-server.js";
import { RemoteDevOAuthProvider } from "../src/oauth.js";

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return port;
}

describe("OAuth endpoint security boundaries", () => {

  it("propagates only verifier-backed OAuth AuthInfo into the MCP request context", async () => {
    const port = await reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const resource = `${baseUrl}/mcp`;
    const config = loadConfig(
      {
        MCP_OAUTH_ENABLED: "true",
        MCP_OAUTH_APPROVAL_KEY: "dummy-approval-value",
        MCP_PUBLIC_URL: baseUrl,
      },
      process.cwd(),
    );
    const authInfo: AuthInfo = {
      token: "dummy-token-value",
      clientId: "verified-oauth-client",
      scopes: ["mcp:tools"],
      expiresAt: Math.floor(Date.now() / 1000) + 300,
      resource: new URL(resource),
    };
    let observedToken: string | undefined;
    const verifier: OAuthTokenVerifier = {
      async verifyAccessToken(token: string) {
        observedToken = token;
        return authInfo;
      },
    };
    const app = express();
    app.post(
      "/mcp",
      createBearerAuth(config, verifier),
      (request, response) => {
        const propagated = (request as typeof request & { auth?: AuthInfo }).auth;
        response.json({
          clientId: propagated?.clientId,
          scopes: propagated?.scopes,
          resource: propagated?.resource?.href,
          tokenPresent: propagated?.token !== undefined,
        });
      },
    );
    const server = await new Promise<ReturnType<typeof app.listen>>((resolve, reject) => {
      const listening = app.listen(port, "127.0.0.1", () => resolve(listening));
      listening.once("error", reject);
    });

    try {
      const response = await fetch(resource, {
        method: "POST",
        headers: {
          authorization: "Bearer dummy-bearer-value",
          "x-auth-client-id": "spoofed-client",
        },
      });
      expect(response.status).toBe(200);
      expect(observedToken).toBe("dummy-bearer-value");
      expect(await response.json()).toEqual({
        clientId: "verified-oauth-client",
        scopes: ["mcp:tools"],
        resource,
        tokenPresent: true,
      });
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }

    const staticPort = await reservePort();
    const staticConfig = loadConfig(
      {
        MCP_AUTH_TOKEN: "dummy-static-value",
      },
      process.cwd(),
    );
    const staticApp = express();
    staticApp.post(
      "/mcp",
      createBearerAuth(staticConfig),
      (request, response) => {
        const propagated = (request as typeof request & { auth?: AuthInfo }).auth;
        response.json({ authInfoPresent: propagated !== undefined });
      },
    );
    const staticServer = await new Promise<ReturnType<typeof staticApp.listen>>(
      (resolve, reject) => {
        const listening = staticApp.listen(staticPort, "127.0.0.1", () =>
          resolve(listening),
        );
        listening.once("error", reject);
      },
    );
    try {
      const response = await fetch(`http://127.0.0.1:${staticPort}/mcp`, {
        method: "POST",
        headers: { authorization: "Bearer dummy-static-value" },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ authInfoPresent: false });
    } finally {
      await new Promise<void>((resolve, reject) => {
        staticServer.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });

  it("does not trust spoofed forwarded IPs unless a proxy is explicitly configured", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(os.tmpdir(), "cokacremote-auth-boundary-test-"),
    );
    const port = await reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const config = loadConfig(
      {
        MCP_OAUTH_ENABLED: "true",
        MCP_OAUTH_APPROVAL_KEY: "oauth-approval-key",
        MCP_PUBLIC_URL: baseUrl,
        MCP_OAUTH_STATE_FILE: path.join(temporaryDirectory, "oauth-state.json"),
        MCP_HOST: "127.0.0.1",
        MCP_PORT: String(port),
        MCP_DEFAULT_CWD: temporaryDirectory,
      },
      temporaryDirectory,
    );
    const running = await startHttpServer(config, createServices(config));

    try {
      const approvalKeyAsBearer = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          authorization: "Bearer oauth-approval-key",
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
      });
      expect(approvalKeyAsBearer.status).toBe(401);

      const statuses: number[] = [];
      for (let index = 1; index <= 21; index += 1) {
        const response = await fetch(`${baseUrl}/register`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": `203.0.113.${index}`,
          },
          body: JSON.stringify({
            redirect_uris: ["https://chatgpt.com/connector/oauth/security-test"],
            token_endpoint_auth_method: "none",
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            client_name: `security-test-${index}`,
            scope: "mcp:tools",
          }),
        });
        statuses.push(response.status);
      }

      expect(statuses.slice(0, 20)).toEqual(Array(20).fill(201));
      expect(statuses[20]).toBe(429);
    } finally {
      await running.close();
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  });

  it("rolls back failed state writes and revokes an entire token grant", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(os.tmpdir(), "cokacremote-oauth-store-test-"),
    );
    const baseEnvironment = {
      MCP_OAUTH_ENABLED: "true",
      MCP_OAUTH_APPROVAL_KEY: "oauth-approval-key",
      MCP_PUBLIC_URL: "http://127.0.0.1:34567",
    };
    const metadata = {
      client_id: "security-store-client",
      redirect_uris: ["https://chatgpt.com/connector/oauth/security-store-test"],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: "security store test",
      scope: "mcp:tools",
    };

    try {
      const blockedDirectory = path.join(temporaryDirectory, "blocked-state-directory");
      await mkdir(blockedDirectory);
      const failedProvider = new RemoteDevOAuthProvider(
        loadConfig(
          {
            ...baseEnvironment,
            MCP_OAUTH_STATE_FILE: path.join(blockedDirectory, "state.json"),
          },
          temporaryDirectory,
        ),
      );
      await expect(
        failedProvider.clientsStore.getClient(metadata.client_id),
      ).resolves.toBeUndefined();
      await rm(blockedDirectory, { recursive: true, force: true });
      await writeFile(blockedDirectory, "block state persistence");
      await expect(
        failedProvider.clientsStore.registerClient(
          metadata as Parameters<typeof failedProvider.clientsStore.registerClient>[0],
        ),
      ).rejects.toThrow();
      await expect(
        failedProvider.clientsStore.getClient(metadata.client_id),
      ).resolves.toBeUndefined();

      const stateFile = path.join(temporaryDirectory, "valid-state.json");
      const provider = new RemoteDevOAuthProvider(
        loadConfig(
          { ...baseEnvironment, MCP_OAUTH_STATE_FILE: stateFile },
          temporaryDirectory,
        ),
      );
      const client = await provider.clientsStore.registerClient(
        metadata as Parameters<typeof provider.clientsStore.registerClient>[0],
      );
      const resource = "http://127.0.0.1:34567/mcp";
      const pair = await provider.clientsStore.issueTokenPair(
        client.client_id,
        ["mcp:tools"],
        resource,
      );
      expect(pair.refresh_token).toBeTypeOf("string");

      await provider.clientsStore.revoke(pair.refresh_token!, client.client_id);

      await expect(
        provider.clientsStore.getAccessToken(pair.access_token),
      ).resolves.toBeUndefined();
      await expect(
        provider.clientsStore.rotateRefreshToken(
          pair.refresh_token!,
          client.client_id,
          resource,
          undefined,
        ),
      ).resolves.toMatchObject({ status: "invalid" });
    } finally {
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  });

  it("propagates only verified OAuth AuthInfo and rejects stale or mismatched verifier output", async () => {
    const temporaryDirectory = await mkdtemp(
      path.join(os.tmpdir(), "cokacremote-auth-propagation-test-"),
    );
    const port = await reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const resource = new URL(`${baseUrl}/mcp`);
    const config = loadConfig(
      {
        MCP_OAUTH_ENABLED: "true",
        MCP_OAUTH_APPROVAL_KEY: "oauth-approval-key",
        MCP_AUTH_TOKEN: "static-generic-token",
        MCP_PUBLIC_URL: baseUrl,
        MCP_OAUTH_STATE_FILE: path.join(temporaryDirectory, "oauth-state.json"),
      },
      temporaryDirectory,
    );
    const future = Math.floor(Date.now() / 1000) + 600;
    const verifier: OAuthTokenVerifier = {
      async verifyAccessToken(token: string): Promise<AuthInfo> {
        if (token === "oauth-valid") {
          return {
            token,
            clientId: "trusted-client",
            scopes: ["mcp:tools"],
            expiresAt: future,
            resource,
          };
        }
        if (token === "oauth-expired") {
          return {
            token,
            clientId: "trusted-client",
            scopes: ["mcp:tools"],
            expiresAt: Math.floor(Date.now() / 1000) - 1,
            resource,
          };
        }
        if (token === "oauth-wrong-resource") {
          return {
            token,
            clientId: "trusted-client",
            scopes: ["mcp:tools"],
            expiresAt: future,
            resource: new URL(`${baseUrl}/other`),
          };
        }
        if (token === "oauth-wrong-scope") {
          return {
            token,
            clientId: "trusted-client",
            scopes: ["mcp:read"],
            expiresAt: future,
            resource,
          };
        }
        throw new Error("invalid token");
      },
    };

    const app = express();
    app.use(express.json());
    app.post(
      "/probe",
      createBearerAuth(config, verifier),
      (request, response) => {
        const auth = (request as typeof request & { auth?: AuthInfo }).auth;
        response.json({
          clientId: auth?.clientId ?? null,
          scopes: auth?.scopes ?? null,
          hasVerifiedAuth: auth !== undefined,
        });
      },
    );
    const server = app.listen(port, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const call = (token: string, forgedClient?: string) =>
      fetch(`${baseUrl}/probe`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          ...(forgedClient ? { "x-mcp-client-id": forgedClient } : {}),
        },
        body: "{}",
      });

    try {
      const valid = await call("oauth-valid", "forged-client");
      expect(valid.status).toBe(200);
      await expect(valid.json()).resolves.toEqual({
        clientId: "trusted-client",
        scopes: ["mcp:tools"],
        hasVerifiedAuth: true,
      });

      const staticBearer = await call("static-generic-token", "forged-client");
      expect(staticBearer.status).toBe(200);
      await expect(staticBearer.json()).resolves.toEqual({
        clientId: null,
        scopes: null,
        hasVerifiedAuth: false,
      });

      for (const token of [
        "oauth-expired",
        "oauth-wrong-resource",
        "oauth-wrong-scope",
      ]) {
        const response = await call(token, "forged-client");
        expect(response.status).toBe(401);
      }

      const forgedOnly = await call("not-a-token", "trusted-client");
      expect(forgedOnly.status).toBe(401);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  });
});
