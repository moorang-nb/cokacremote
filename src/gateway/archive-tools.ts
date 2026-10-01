import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  ErrorCode,
  McpError,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";

import {
  ArchiveBridgeClient,
  type ArchiveBridgeOperation,
} from "./archive-bridge-client.js";

export const ARCHIVE_TOOL_NAMES = {
  prepare: "archive_source_draft_prepare",
  preview: "archive_source_draft_preview",
  decide: "archive_source_draft_decide",
} as const;

const PREPARE_ARTIFACTS = [
  "manifest.json",
  "value_payload.json",
  "raw_inventory.json",
  "accountability_ledger.json",
  "validation_receipt.json",
  "rendered_lore.md",
] as const;
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;

type ArchiveToolName = (typeof ARCHIVE_TOOL_NAMES)[keyof typeof ARCHIVE_TOOL_NAMES];

const projectKeySchema = {
  type: "string",
  minLength: 1,
  maxLength: 128,
  description:
    "Bounded logical project selector resolved by host policy. It is not a filesystem path.",
};

const targetOperationSchema = {
  type: "string",
  pattern: UUID_V4.source,
  description: "Semantic operation UUID returned by a prior Archive draft request.",
};

export const ARCHIVE_TOOLS: Tool[] = [
  {
    name: ARCHIVE_TOOL_NAMES.prepare,
    title: "Prepare Archive source draft",
    description:
      "Submit the fixed six source-draft artifacts for an already enrolled logical project. The receiving host selects all filesystem and protected execution authority.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        project_key: projectKeySchema,
        artifacts: {
          type: "object",
          additionalProperties: false,
          properties: Object.fromEntries(
            PREPARE_ARTIFACTS.map((name) => [
              name,
              { type: "string", minLength: 1 },
            ]),
          ),
          required: [...PREPARE_ARTIFACTS],
        },
      },
      required: ["project_key", "artifacts"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: ARCHIVE_TOOL_NAMES.preview,
    title: "Preview Archive source draft",
    description:
      "Read the bounded owner result for a prior Archive source-draft semantic operation without selecting a filesystem path or native action.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        target_operation_id: targetOperationSchema,
      },
      required: ["target_operation_id"],
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: ARCHIVE_TOOL_NAMES.decide,
    title: "Decide Archive source draft",
    description:
      "Relay an explicit user decision for a prior Archive source-draft operation. Approval requires parallel-session approval evidence.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        target_operation_id: targetOperationSchema,
        binding_sha256: { type: "string", pattern: SHA256.source },
        decision_id: { type: "string", pattern: UUID_V4.source },
        decision: { type: "string", enum: ["approved", "rejected", "cancelled"] },
        user_message: { type: "string", minLength: 1, maxLength: 4096 },
        message_reference: {
          anyOf: [
            { type: "string", minLength: 1, maxLength: 4096 },
            { type: "null" },
          ],
        },
        decided_at: { type: "string", format: "date-time" },
        expires_at: { type: "string", format: "date-time" },
        parallel_session_approved: { type: "boolean" },
      },
      required: [
        "target_operation_id",
        "binding_sha256",
        "decision_id",
        "decision",
        "user_message",
        "message_reference",
        "decided_at",
        "expires_at",
        "parallel_session_approved",
      ],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
];

function objectArgs(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new McpError(ErrorCode.InvalidParams, "Archive tool arguments must be an object");
  }
  const args = value as Record<string, unknown>;
  const keys = Object.keys(args);
  if (
    keys.length !== fields.length ||
    keys.some((key) => !fields.includes(key))
  ) {
    throw new McpError(ErrorCode.InvalidParams, "Archive tool argument fields are invalid");
  }
  return args;
}

function projectKey(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 128 ||
    value !== value.trim() ||
    value === "." ||
    value === ".." ||
    /[\\/\x00-\x1f\x7f]/.test(value)
  ) {
    throw new McpError(ErrorCode.InvalidParams, "project_key is not a bounded logical selector");
  }
  return value;
}

function uuid(value: unknown, field: string): string {
  if (typeof value !== "string" || !UUID_V4.test(value)) {
    throw new McpError(ErrorCode.InvalidParams, `${field} must be a lowercase UUIDv4`);
  }
  return value;
}

function sha(value: unknown, field: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new McpError(ErrorCode.InvalidParams, `${field} must be a lowercase SHA-256`);
  }
  return value;
}

function nonemptyText(value: unknown, field: string, nullable = false): string | null {
  if (nullable && value === null) {
    return null;
  }
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 4096 ||
    value.includes("\x00")
  ) {
    throw new McpError(ErrorCode.InvalidParams, `${field} is invalid`);
  }
  return value;
}

function utcDate(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.endsWith("Z")) {
    throw new McpError(ErrorCode.InvalidParams, `${field} must be UTC with Z suffix`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new McpError(ErrorCode.InvalidParams, `${field} is not a valid timestamp`);
  }
  return value;
}

function preparePayload(value: unknown): Record<string, unknown> {
  const args = objectArgs(value, ["project_key", "artifacts"]);
  const logicalProject = projectKey(args.project_key);
  const artifacts = objectArgs(args.artifacts, PREPARE_ARTIFACTS);
  let total = 0;
  const normalized: Record<string, string> = {};
  for (const name of PREPARE_ARTIFACTS) {
    const content = artifacts[name];
    if (typeof content !== "string" || !content || content.includes("\x00")) {
      throw new McpError(ErrorCode.InvalidParams, `${name} must be non-empty UTF-8 text`);
    }
    total += Buffer.byteLength(content, "utf8");
    if (total > 4 * 1024 * 1024) {
      throw new McpError(ErrorCode.InvalidParams, "Prepare artifacts exceed 4 MiB");
    }
    normalized[name] = content;
  }
  return { project_key: logicalProject, artifacts: normalized };
}

function previewPayload(value: unknown): Record<string, unknown> {
  const args = objectArgs(value, ["target_operation_id"]);
  return {
    target_operation_id: uuid(args.target_operation_id, "target_operation_id"),
  };
}

function decidePayload(value: unknown): Record<string, unknown> {
  const fields = [
    "target_operation_id",
    "binding_sha256",
    "decision_id",
    "decision",
    "user_message",
    "message_reference",
    "decided_at",
    "expires_at",
    "parallel_session_approved",
  ] as const;
  const args = objectArgs(value, fields);
  if (
    args.decision !== "approved" &&
    args.decision !== "rejected" &&
    args.decision !== "cancelled"
  ) {
    throw new McpError(ErrorCode.InvalidParams, "decision is invalid");
  }
  if (typeof args.parallel_session_approved !== "boolean") {
    throw new McpError(ErrorCode.InvalidParams, "parallel_session_approved must be boolean");
  }
  if (args.decision === "approved" && args.parallel_session_approved !== true) {
    throw new McpError(
      ErrorCode.InvalidParams,
      "approved decision requires parallel_session_approved=true",
    );
  }
  const decidedAt = utcDate(args.decided_at, "decided_at");
  const expiresAt = utcDate(args.expires_at, "expires_at");
  if (Date.parse(expiresAt) <= Date.parse(decidedAt)) {
    throw new McpError(ErrorCode.InvalidParams, "expires_at must be later than decided_at");
  }
  return {
    target_operation_id: uuid(args.target_operation_id, "target_operation_id"),
    binding_sha256: sha(args.binding_sha256, "binding_sha256"),
    decision_id: uuid(args.decision_id, "decision_id"),
    decision: args.decision,
    user_message: nonemptyText(args.user_message, "user_message"),
    message_reference: nonemptyText(args.message_reference, "message_reference", true),
    decided_at: decidedAt,
    expires_at: expiresAt,
    parallel_session_approved: args.parallel_session_approved,
  };
}

function operationFor(name: ArchiveToolName): ArchiveBridgeOperation {
  if (name === ARCHIVE_TOOL_NAMES.prepare) {
    return "source_draft_prepare";
  }
  if (name === ARCHIVE_TOOL_NAMES.preview) {
    return "source_draft_preview";
  }
  return "source_draft_decide";
}

export function isArchiveToolName(name: string): name is ArchiveToolName {
  return Object.values(ARCHIVE_TOOL_NAMES).includes(name as ArchiveToolName);
}

export async function callArchiveTool(
  client: ArchiveBridgeClient,
  name: ArchiveToolName,
  rawArguments: unknown,
  authInfo: AuthInfo | undefined,
): Promise<CallToolResult> {
  const payload =
    name === ARCHIVE_TOOL_NAMES.prepare
      ? preparePayload(rawArguments)
      : name === ARCHIVE_TOOL_NAMES.preview
        ? previewPayload(rawArguments)
        : decidePayload(rawArguments);
  const result = await client.submit(operationFor(name), payload, authInfo);
  const structuredContent = {
    bridgeRequestId: result.bridgeRequestId,
    state: result.state,
    reasonCode: result.reasonCode,
    relayOperationId: result.relayOperationId,
    ownerObservation: result.ownerObservation,
    presentation: result.presentation,
    automaticResubmissionAllowed: result.automaticResubmissionAllowed,
    createdAt: result.createdAt,
    pending: result.pending,
  };
  return {
    structuredContent,
    content: [{ type: "text", text: JSON.stringify(structuredContent) }],
    isError: result.state === "RECOVERY_REQUIRED",
  };
}
