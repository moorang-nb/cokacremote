import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
} from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  unlink,
} from "node:fs/promises";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

import type { AppConfig } from "../config.js";

export const BRIDGE_REQUEST_SCHEMA = "aias-receiving-host-bridge-request-v1";
export const BRIDGE_RESULT_SCHEMA = "aias-receiving-host-bridge-result-v1";

export type ArchiveBridgeOperation =
  | "source_draft_prepare"
  | "source_draft_preview"
  | "source_draft_decide";

export interface ArchiveBridgeSubmission {
  bridgeRequestId: string;
  state: string;
  reasonCode: string;
  relayOperationId: string | null;
  ownerObservation: unknown | null;
  presentation: unknown | null;
  automaticResubmissionAllowed: false;
  createdAt: number | null;
  pending: boolean;
}

interface OAuthProjection {
  client_id: string;
  scopes: string[];
  resource: string;
  expires_at: number;
}

interface BridgeRequestUnsigned {
  schema_version: typeof BRIDGE_REQUEST_SCHEMA;
  bridge_generation: number;
  bridge_request_id: string;
  created_at: number;
  expires_at: number;
  nonce: string;
  gateway_source_fingerprint: string;
  oauth: OAuthProjection;
  operation: ArchiveBridgeOperation;
  semantic_payload: unknown;
  semantic_sha256: string;
}

interface BridgeRequest extends BridgeRequestUnsigned {
  mac_sha256: string;
}

interface BridgeResult {
  schema_version: typeof BRIDGE_RESULT_SCHEMA;
  bridge_request_id: string;
  state: string;
  reason_code: string;
  relay_operation_id: string | null;
  owner_observation: unknown | null;
  presentation: unknown | null;
  automatic_resubmission_allowed: false;
  created_at: number;
  result_sha256: string;
}

const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const BRIDGE_RESULT_STATES = new Set([
  "RECEIVED",
  "CLAIMED",
  "ENVELOPE_RESERVED",
  "SEND_ATTEMPTED",
  "RESULT_OBSERVED",
  "RECOVERY_REQUIRED",
]);

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, item]) => [key, canonicalValue(item)]),
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function resultDigest(result: Omit<BridgeResult, "result_sha256">): string {
  return sha256(result);
}

async function secureDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const status = await lstat(directory);
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new McpError(ErrorCode.InternalError, "Bridge exchange path is not a real directory");
  }
  const lexical = path.resolve(directory);
  const physical = await realpath(directory);
  if (physical !== lexical) {
    throw new McpError(
      ErrorCode.InternalError,
      "Bridge exchange path traverses a symbolic link",
    );
  }
}

function requireGatewayConfig(config: AppConfig): {
  root: string;
  keyFile: string;
  generation: number;
  fingerprint: string;
  resource: string;
} {
  if (
    config.mode !== "gateway" ||
    !config.bridgeExchangeRoot ||
    !config.bridgeAttestationKeyFile ||
    !config.bridgeGeneration ||
    !config.gatewaySourceFingerprint ||
    !config.oauthResourceUrl
  ) {
    throw new McpError(ErrorCode.InternalError, "Gateway bridge configuration is incomplete");
  }
  return {
    root: config.bridgeExchangeRoot,
    keyFile: config.bridgeAttestationKeyFile,
    generation: config.bridgeGeneration,
    fingerprint: config.gatewaySourceFingerprint,
    resource: new URL(config.oauthResourceUrl).href,
  };
}

function projectAuth(config: AppConfig, authInfo: AuthInfo | undefined): OAuthProjection {
  if (!authInfo) {
    throw new McpError(ErrorCode.InvalidRequest, "Archive tools require verified OAuth AuthInfo");
  }
  const now = Math.floor(Date.now() / 1000);
  if (
    authInfo.expiresAt === undefined ||
    !Number.isFinite(authInfo.expiresAt) ||
    authInfo.expiresAt <= now
  ) {
    throw new McpError(ErrorCode.InvalidRequest, "OAuth credential is expired or lacks expiry");
  }
  const expectedResource = requireGatewayConfig(config).resource;
  if (!authInfo.resource || authInfo.resource.href !== expectedResource) {
    throw new McpError(ErrorCode.InvalidRequest, "OAuth resource is not authorized for Archive");
  }
  const scopes = [...new Set(authInfo.scopes)].sort();
  if (!scopes.includes("mcp:tools")) {
    throw new McpError(ErrorCode.InvalidRequest, "OAuth scope does not authorize MCP tools");
  }
  if (!authInfo.clientId.trim()) {
    throw new McpError(ErrorCode.InvalidRequest, "OAuth client identity is missing");
  }
  return {
    client_id: authInfo.clientId,
    scopes,
    resource: expectedResource,
    expires_at: Math.floor(authInfo.expiresAt),
  };
}

async function attestationKey(filename: string): Promise<Buffer> {
  const status = await lstat(filename);
  if (!status.isFile() || status.isSymbolicLink()) {
    throw new McpError(ErrorCode.InternalError, "Bridge attestation key is not a real file");
  }
  const lexical = path.resolve(filename);
  const physical = await realpath(filename);
  if (physical !== lexical) {
    throw new McpError(
      ErrorCode.InternalError,
      "Bridge attestation key path traverses a symbolic link",
    );
  }
  const raw = await readFile(filename);
  const normalized = Buffer.from(raw.toString("utf8").trim(), "utf8");
  if (normalized.length < 32) {
    throw new McpError(ErrorCode.InternalError, "Bridge attestation key is too short");
  }
  return normalized;
}

async function publishExclusive(filename: string, bytes: Buffer): Promise<void> {
  const directory = path.dirname(filename);
  const temporary = path.join(directory, `.${path.basename(filename)}.${randomUUID()}.tmp`);
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await link(temporary, filename);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST") {
      throw new McpError(ErrorCode.InvalidRequest, "Bridge request identity collision");
    }
    throw error;
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
}

function closedResult(value: unknown, expectedRequestId: string): BridgeResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new McpError(ErrorCode.InternalError, "Bridge result is not an object");
  }
  const result = value as Record<string, unknown>;
  const expectedFields = new Set([
    "schema_version",
    "bridge_request_id",
    "state",
    "reason_code",
    "relay_operation_id",
    "owner_observation",
    "presentation",
    "automatic_resubmission_allowed",
    "created_at",
    "result_sha256",
  ]);
  if (
    Object.keys(result).length !== expectedFields.size ||
    Object.keys(result).some((field) => !expectedFields.has(field))
  ) {
    throw new McpError(ErrorCode.InternalError, "Bridge result fields are invalid");
  }
  if (
    result.schema_version !== BRIDGE_RESULT_SCHEMA ||
    result.bridge_request_id !== expectedRequestId ||
    typeof result.state !== "string" ||
    !BRIDGE_RESULT_STATES.has(result.state) ||
    typeof result.reason_code !== "string" ||
    !result.reason_code ||
    result.reason_code.length > 256 ||
    /[\x00-\x1f\x7f]/.test(result.reason_code) ||
    result.automatic_resubmission_allowed !== false ||
    typeof result.created_at !== "number" ||
    !Number.isSafeInteger(result.created_at) ||
    typeof result.result_sha256 !== "string" ||
    !SHA256.test(result.result_sha256)
  ) {
    throw new McpError(ErrorCode.InternalError, "Bridge result identity is invalid");
  }
  if (
    result.relay_operation_id !== null &&
    (typeof result.relay_operation_id !== "string" || !UUID_V4.test(result.relay_operation_id))
  ) {
    throw new McpError(ErrorCode.InternalError, "Bridge relay operation identity is invalid");
  }
  const unsigned: Omit<BridgeResult, "result_sha256"> = {
    schema_version: BRIDGE_RESULT_SCHEMA,
    bridge_request_id: expectedRequestId,
    state: result.state,
    reason_code: result.reason_code,
    relay_operation_id: result.relay_operation_id,
    owner_observation: result.owner_observation ?? null,
    presentation: result.presentation ?? null,
    automatic_resubmission_allowed: false,
    created_at: result.created_at,
  };
  if (resultDigest(unsigned) !== result.result_sha256) {
    throw new McpError(ErrorCode.InternalError, "Bridge result digest mismatch");
  }
  return { ...unsigned, result_sha256: result.result_sha256 };
}

export class ArchiveBridgeClient {
  constructor(private readonly config: AppConfig) {}

  private async waitForResult(
    resultFile: string,
    bridgeRequestId: string,
  ): Promise<BridgeResult | undefined> {
    const deadline = Date.now() + this.config.bridgeResultWaitMs;
    while (true) {
      try {
        const status = await lstat(resultFile);
        if (!status.isFile() || status.isSymbolicLink()) {
          throw new McpError(
            ErrorCode.InternalError,
            "Bridge result path is not a real file",
          );
        }
        const lexical = path.resolve(resultFile);
        const physical = await realpath(resultFile);
        if (physical !== lexical) {
          throw new McpError(
            ErrorCode.InternalError,
            "Bridge result path traverses a symbolic link",
          );
        }
        const raw = await readFile(resultFile);
        if (raw.length > 2 * 1024 * 1024) {
          throw new McpError(ErrorCode.InternalError, "Bridge result exceeds size limit");
        }
        return closedResult(JSON.parse(raw.toString("utf8")), bridgeRequestId);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
      if (Date.now() >= deadline) {
        return undefined;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  async submit(
    operation: ArchiveBridgeOperation,
    semanticPayload: unknown,
    authInfo: AuthInfo | undefined,
  ): Promise<ArchiveBridgeSubmission> {
    const oauth = projectAuth(this.config, authInfo);
    const fixed = requireGatewayConfig(this.config);
    const createdAt = Math.floor(Date.now() / 1000);
    const expiresAt = Math.min(
      createdAt + this.config.bridgeRequestTtlSeconds,
      oauth.expires_at,
    );
    if (expiresAt <= createdAt) {
      throw new McpError(ErrorCode.InvalidRequest, "OAuth lifetime is too short for bridge request");
    }

    await secureDirectory(fixed.root);
    const requests = path.join(fixed.root, "requests");
    const results = path.join(fixed.root, "results");
    await secureDirectory(requests);
    await secureDirectory(results);

    const bridgeRequestId = randomUUID();
    const unsigned: BridgeRequestUnsigned = {
      schema_version: BRIDGE_REQUEST_SCHEMA,
      bridge_generation: fixed.generation,
      bridge_request_id: bridgeRequestId,
      created_at: createdAt,
      expires_at: expiresAt,
      nonce: randomBytes(16).toString("hex"),
      gateway_source_fingerprint: fixed.fingerprint,
      oauth,
      operation,
      semantic_payload: semanticPayload,
      semantic_sha256: sha256(semanticPayload),
    };
    const key = await attestationKey(fixed.keyFile);
    const request: BridgeRequest = {
      ...unsigned,
      mac_sha256: createHmac("sha256", key).update(canonicalJson(unsigned), "utf8").digest("hex"),
    };
    const requestBytes = Buffer.from(canonicalJson(request) + "\n", "utf8");
    if (requestBytes.length > 32 * 1024 * 1024) {
      throw new McpError(ErrorCode.InvalidParams, "Bridge request exceeds size limit");
    }

    const requestFile = path.join(requests, `${bridgeRequestId}.json`);
    const resultFile = path.join(results, `${bridgeRequestId}.json`);
    await publishExclusive(requestFile, requestBytes);

    const result = await this.waitForResult(resultFile, bridgeRequestId);
    if (!result) {
      return {
        bridgeRequestId,
        state: "PENDING",
        reasonCode: "RESULT_NOT_YET_OBSERVED",
        relayOperationId: null,
        ownerObservation: null,
        presentation: null,
        automaticResubmissionAllowed: false,
        createdAt: null,
        pending: true,
      };
    }
    return {
      bridgeRequestId,
      state: result.state,
      reasonCode: result.reason_code,
      relayOperationId: result.relay_operation_id,
      ownerObservation: result.owner_observation,
      presentation: result.presentation,
      automaticResubmissionAllowed: false,
      createdAt: result.created_at,
      pending: false,
    };
  }
}
