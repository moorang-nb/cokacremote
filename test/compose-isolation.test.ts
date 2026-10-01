import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

function serviceBlock(source: string, name: string, nextName?: string): string {
  const startMarker = `  ${name}:\n`;
  const start = source.indexOf(startMarker);
  if (start < 0) {
    throw new Error(`missing compose service: ${name}`);
  }
  const end = nextName
    ? source.indexOf(`  ${nextName}:\n`, start + startMarker.length)
    : source.indexOf("\nnetworks:\n", start + startMarker.length);
  if (end < 0) {
    throw new Error(`cannot bound compose service: ${name}`);
  }
  return source.slice(start, end);
}

describe("gateway/backend compose isolation contract", () => {
  it("keeps public gateway mounts and private generic mounts disjoint", async () => {
    const compose = await readFile(
      new URL("../tunneling/docker-compose.yml", import.meta.url),
      "utf8",
    );
    const gateway = serviceBlock(compose, "workmachine", "generic-backend");
    const backend = serviceBlock(compose, "generic-backend", "cloudflared");
    const cloudflared = serviceBlock(compose, "cloudflared");

    expect(gateway).toContain("MCP_MODE: gateway");
    expect(gateway).toContain(
      'MCP_GENERIC_BACKEND_URL: "http://generic-backend:3000/mcp"',
    );
    expect(gateway).not.toContain("target: /shared");
    expect(gateway).toContain("target: /var/lib/cokacremote");
    expect(gateway).toContain("target: /var/lib/aias-bridge/exchange");
    expect(gateway).toContain(
      "target: /run/secrets/aias-bridge-attestation-key",
    );
    expect(gateway).toContain("read_only: true");
    expect(gateway).toContain("WORKMACHINE_CONTAINER_NAME");

    expect(backend).toContain("MCP_MODE: generic-backend");
    expect(backend).toContain('MCP_ALLOW_NO_AUTH: "true"');
    expect(backend).toContain('MCP_OAUTH_ENABLED: "false"');
    expect(backend).toContain("target: /shared");
    expect(backend).not.toContain("target: /var/lib/cokacremote");
    expect(backend).not.toContain("target: /var/lib/aias-bridge/exchange");
    expect(backend).not.toContain(
      "target: /run/secrets/aias-bridge-attestation-key",
    );
    expect(backend).toContain("GENERIC_BACKEND_CONTAINER_NAME");

    expect(compose).not.toContain("internal: true");
    expect(cloudflared).toContain('network_mode: "service:workmachine"');
    expect(cloudflared).toContain("CLOUDFLARED_CONTAINER_NAME");
    expect(compose).toContain("COKACREMOTE_REPOSITORY:");
    expect(compose).toContain("COKACREMOTE_REF:");
  });

  it("keeps generic-backend startup out of OAuth and public proxy ownership", async () => {
    const dockerfile = await readFile(
      new URL("../tunneling/Dockerfile", import.meta.url),
      "utf8",
    );
    expect(dockerfile).toContain("MCP_MODE=monolith");
    expect(dockerfile).toContain(
      'if [[ "${mode}" == "generic-backend" ]]; then',
    );
    expect(dockerfile).toContain(
      'if [[ "${MCP_OAUTH_ENABLED:-false}" == "true" ]]; then',
    );
    expect(dockerfile).toContain(
      'echo "generic-backend mode must not enable OAuth" >&2',
    );
    expect(dockerfile).toContain("exec /usr/bin/npm start");
    expect(dockerfile).toContain(
      'if [[ "${mode}" == "generic-backend" && -d /shared',
    );
  });
});
