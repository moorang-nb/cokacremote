import { z } from "zod";
import { createHash } from "node:crypto";
import { ErrorCode, McpError, type Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ArchiveBridgeSubmission } from "./archive-bridge-client.js";

export const CREATIVE_BRIDGE_REQUEST_SCHEMA = "aias-receiving-host-bridge-request-v2";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const uuid = z.string().length(36).regex(UUID);
const sha = z.string().length(64).regex(SHA);
const selector = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/).refine(value => value === value.trim())
  .describe("Enrolled project key or configured alias returned by archive_project_list; never a path.");

/** Reject replacement encoding as well as byte overflow, without normalizing evidence. */
function text(maxBytes: number, allowWhitespace = false) {
  return z.string().min(1).max(maxBytes).refine(value =>
    !value.includes("\0") && (allowWhitespace || value.trim().length > 0) &&
    Buffer.from(value, "utf8").toString("utf8") === value && Buffer.byteLength(value, "utf8") <= maxBytes,
    `Must be valid UTF-8 text of at most ${maxBytes} bytes`);
}
const context = z.strictObject({
  conversation_correlation: text(256).describe("Current conversation's stable audit label. This is not authentication or permission to adopt a session."),
  user_message: text(4096).describe("The actual user request, preserved as evidence."),
  message_reference: text(4096).nullable(),
});
const utc = z.iso.datetime({ offset: false }).max(64).refine(value => value === value.trim());
const decision = z.strictObject({
  binding_sha256: sha.describe("Exact binding digest from the original preview/card."),
  decision_id: uuid.describe("Identity of the actual relayed decision evidence; do not replace on retry."),
  decision: z.enum(["approved", "rejected", "cancelled"]),
  user_message: text(4096).describe("Actual explicit user decision for the shown content/card; never invent approval."),
  message_reference: text(4096).nullable(), decided_at: utc, expires_at: utc,
}).refine(value => Date.parse(value.expires_at) > Date.parse(value.decided_at), "Decision expiry must follow decision time");
const component = text(512).refine(value => value === value.trim() && value !== "." && value !== ".." &&
  !value.endsWith(".") && !/[\x00-\x1f\x7f/\\:*?"<>|]/.test(value) &&
  !/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(value), "Expected semantic document name, never a path");
const documentType = z.enum(["LORE", "STORY", "PUB", "SUMMARY", "MEMO", "LOG", "PROJECT", "INDEX", "PREFACE", "TERM"]);
const documentSelector = {
  document_type: documentType, document_id: component,
  area: z.enum(["project", "private", "memo", "glossary"]), category: z.union([z.literal(""), component]),
};
const document = z.strictObject({ ...documentSelector,
  document_type: documentType.exclude(["LORE"]), content: text(4 * 1024 * 1024, true),
  expected_sha256: z.union([z.literal("ABSENT"), sha]).describe("ABSENT for a new document; otherwise exact current content SHA256."),
});
const project = z.strictObject({
  project_name: z.string().regex(/^[0-9A-Za-z가-힣][0-9A-Za-z가-힣 _.-]{0,79}$/)
    .refine(value => value === value.trim() && !value.endsWith(".") && !/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(value)),
  project_type: z.enum(["general", "narrative", "lore_setting", "toolbox_canon", "system_mechanic", "testbed"]),
  toolboxes: z.array(z.string().regex(/^[0-9A-Za-z가-힣][0-9A-Za-z가-힣_-]{0,63}$/).refine(value => value === value.trim())).max(64)
    .refine(items => new Set(items.map(item => item.toLowerCase())).size === items.length),
  include_world_summary: z.boolean(), include_memo: z.boolean(), branching: z.boolean(),
});
const limit = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const limits = z.strictObject({ max_hot_bytes: limit, max_total_bytes: limit,
  warning_threshold_bytes: limit, required_recovery_headroom_bytes: limit,
}).refine(value => 0 < value.warning_threshold_bytes && value.warning_threshold_bytes <= value.max_hot_bytes &&
  value.max_hot_bytes <= value.max_total_bytes && value.required_recovery_headroom_bytes < value.max_total_bytes);
const ARTIFACT_NAMES = ["manifest.json", "value_payload.json", "raw_inventory.json", "accountability_ledger.json", "validation_receipt.json", "rendered_lore.md"] as const;
const artifact = text(4 * 1024 * 1024, true);
const artifacts = z.strictObject({
  "manifest.json": artifact, "value_payload.json": artifact, "raw_inventory.json": artifact,
  "accountability_ledger.json": artifact, "validation_receipt.json": artifact, "rendered_lore.md": artifact,
}).refine(value => ARTIFACT_NAMES.reduce((sum, name) => sum + Buffer.byteLength(value[name], "utf8"), 0) <= 4 * 1024 * 1024,
  "The six canonical artifacts together must not exceed 4 MiB");
const parallelDecision = z.strictObject({ decision, previous_decision_sha256: sha.nullable() })
  .refine(value => Date.parse(value.decision.expires_at) - Date.parse(value.decision.decided_at) <= 30 * 60 * 1000);
const wrap = <T extends z.ZodType>(payload: T) => z.strictObject({ project_key: selector, payload });

/** Retain exact text while rejecting duplicate keys, invalid scalars and excessive graphs. */
function writerJson(raw: string): Record<string, any> {
  if (Buffer.byteLength(raw, "utf8") > 1024 * 1024) throw new Error("writer JSON size");
  const value: unknown = JSON.parse(raw);
  const containers: { object: boolean; key: boolean; keys: Set<string> }[] = [];
  const tokens = raw.match(/"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^\s{}\[\],:]+/g) ?? [];
  for (const token of tokens) {
    if (token === "{" || token === "[") {
      containers.push({ object: token === "{", key: token === "{", keys: new Set() });
      if (containers.length > 25) throw new Error("writer depth");
    } else if (token === "}" || token === "]") containers.pop();
    else if (token === ",") { const top = containers.at(-1); if (top?.object) top.key = true; }
    else if (token.startsWith('"')) {
      const top = containers.at(-1);
      if (top?.object && top.key) {
        const key: string = JSON.parse(token);
        if (top.keys.has(key)) throw new Error("writer duplicate key");
        top.keys.add(key); top.key = false;
      }
    }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("writer object");
  const pending: [unknown, number][] = [[value, 0]];
  let count = 0;
  while (pending.length) {
    const [item, depth] = pending.pop()!;
    if (++count > 65536 || depth > 24) throw new Error("writer complexity");
    if (typeof item === "string") {
      if (item.includes("\0") || Buffer.from(item, "utf8").toString("utf8") !== item || Buffer.byteLength(item, "utf8") > 256 * 1024) throw new Error("writer string");
    } else if (typeof item === "number") {
      if (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item))) throw new Error("writer number");
    } else if (Array.isArray(item)) pending.push(...item.map(child => [child, depth + 1] as [unknown, number]));
    else if (item !== null && typeof item === "object") {
      for (const [key, child] of Object.entries(item)) {
        if (!text(512).safeParse(key).success) throw new Error("writer key");
        pending.push([child, depth + 1]);
      }
    }
  }
  return value as Record<string, any>;
}
const writerEntry = z.strictObject({
  state: z.enum(["set", "unset", "deferred", "intentional_none", "not_applicable"]), value: z.unknown(),
  reason: z.union([z.literal(""), text(16384, true)]).nullable(),
  revisit_condition: z.union([z.literal(""), text(16384, true)]).nullable(),
  evidence: z.array(text(16384)).max(128), confidence: z.number().min(0).max(1).nullable(),
});
const writerResponse = z.strictObject({ schema_version: z.literal("lore-writer-production-response-v1"),
  request_sha256: sha, values: z.strictObject({ subject_id: component, status: z.enum(["draft", "confirmed"]),
    fields: z.record(text(512), writerEntry).refine(value => Object.keys(value).length <= 4096) }),
});
const writerScope = z.strictObject({
  Definitiveness: z.enum(["definitive", "exploratory", "foreshadowing", "reverse", "delegated", "operational"]),
  Expression: z.strictObject({ Typicality: z.number().int().min(0).max(100), Depth: z.number().int().min(0).max(100) }),
});
const writerContext = z.strictObject({ context, intent: z.enum(["create", "revise"]),
  toolbox_id: component.nullable(), compass_id: component.nullable(), category: component.nullable(), title: component.nullable(),
  source_id: component.nullable(), brief: text(16384), summary: z.union([z.literal(""), text(4096, true)]).nullable(),
  scope: writerScope.nullable(), change_keys: z.array(text(512)).max(4096).refine(items => new Set(items).size === items.length),
  status: z.enum(["draft", "confirmed"]),
}).refine(value => value.intent === "create"
  ? value.toolbox_id !== null && value.compass_id !== null && value.category !== null && !value.category.includes("_") &&
    value.title !== null && value.source_id === null && value.change_keys.length === 0 && value.scope !== null &&
    value.summary !== null && !/[\x00-\x1f]/.test(value.summary)
  : value.source_id !== null && value.change_keys.length > 0 &&
    [value.toolbox_id, value.compass_id, value.category, value.title, value.summary, value.scope].every(item => item === null));
const writerRender = z.strictObject({ context, target_bridge_request_id: uuid, request_sha256: sha,
  writer_reference: text(4096).describe("Audit correlation only, not proof that a separate writer ran."),
  writer_output_json: text(1024 * 1024).describe("Exact UTF-8 JSON text of {schema_version:'lore-writer-production-response-v1',request_sha256,values:{subject_id,status,fields}}. Each field has state,value,reason,revisit_condition,evidence,confidence. Return all stable keys from the original writer request; do not supply Markdown or receipts."),
}).refine(value => {
  try { const output = writerResponse.parse(writerJson(value.writer_output_json)); return output.request_sha256 === value.request_sha256; }
  catch { return false; }
}, "Invalid or unbound writer JSON; exact text is preserved without reserialization");

export const CREATIVE_SCHEMAS = {
  project_connect: z.strictObject({ project_key: selector.optional(), payload: z.strictObject({ context,
    project_name: project.shape.project_name, project_type: project.shape.project_type }) }),
  project_provision_preview: z.strictObject({ project_key: selector.optional(), payload: z.strictObject({ context, project }) }),
  project_provision_decide: wrap(z.strictObject({ context, target_operation_id: uuid, decision })),
  project_support_status: wrap(z.strictObject({ context })),
  project_session_status: wrap(z.strictObject({ context })),
  project_session_activate: wrap(z.strictObject({ context, target_state_operation_id: uuid })),
  project_session_open: wrap(z.strictObject({ context, target_state_operation_id: uuid,
    open_intent_sha256: sha, observed_active_sessions_sha256: sha, parallel_decision: parallelDecision.nullable() })),
  project_session_close: wrap(z.strictObject({ context, target_open_operation_id: uuid, summary: text(4096) })),
  project_document_prepare: wrap(z.strictObject({ context, target_open_operation_id: uuid, document })),
  project_document_preview: wrap(z.strictObject({ context, target_operation_id: uuid })),
  project_document_decide: wrap(z.strictObject({ context, target_operation_id: uuid, target_open_operation_id: uuid, decision })),
  project_document_read: wrap(z.strictObject({ context, document: z.strictObject(documentSelector) })),
  project_lore_prepare: wrap(z.strictObject({ context, target_open_operation_id: uuid, artifacts })),
  project_lore_preview: wrap(z.strictObject({ context, target_operation_id: uuid })),
  project_lore_decide: wrap(z.strictObject({ context, target_operation_id: uuid, target_open_operation_id: uuid, decision })),
  project_storage_status: wrap(z.strictObject({ context })),
  project_storage_prepare: wrap(z.strictObject({ context, limits })),
  project_storage_decide: wrap(z.strictObject({ context, target_operation_id: uuid, decision })),
  project_context_read: z.strictObject({ project_key: selector,
    scopes: z.array(z.enum(["index", "project", "log", "summary"])).min(1).max(4).refine(items => new Set(items).size === items.length),
    max_bytes_per_document: z.number().int().min(1024).max(262144) }),
  operation_result_read: z.strictObject({ target_operation_id: uuid }),
  project_lore_writer_context: wrap(writerContext),
  project_lore_writer_render: wrap(writerRender),
  project_list: z.strictObject({}),
  bridge_result_read: z.strictObject({ target_bridge_request_id: uuid }),
} as const;
export type CreativeBridgeOperation = keyof typeof CREATIVE_SCHEMAS;
export type CreativeToolName = `archive_${CreativeBridgeOperation}`;
export const CREATIVE_OPERATIONS = Object.keys(CREATIVE_SCHEMAS) as CreativeBridgeOperation[];

export function isCreativeOperation(value: string): value is CreativeBridgeOperation {
  return Object.hasOwn(CREATIVE_SCHEMAS, value);
}
export function isCreativeToolName(value: string): value is CreativeToolName {
  return value.startsWith("archive_") && isCreativeOperation(value.slice(8));
}
export function creativeOperationFor(name: CreativeToolName): CreativeBridgeOperation {
  const operation = name.slice(8);
  if (!isCreativeOperation(operation)) throw new McpError(ErrorCode.InvalidParams, "Unknown Archive operation");
  return operation;
}
export function validateCreativeArguments(operation: CreativeBridgeOperation, raw: unknown): Record<string, unknown> {
  const parsed = CREATIVE_SCHEMAS[operation].safeParse(raw);
  if (!parsed.success) throw new McpError(ErrorCode.InvalidParams, "Archive creative arguments do not match the closed operation schema");
  if ((operation === "project_provision_preview" || operation === "project_connect") && !("project_key" in parsed.data)) {
    const value = parsed.data as { payload: { project?: { project_name: string }; project_name?: string } };
    const name = operation === "project_connect" ? value.payload.project_name! : value.payload.project!.project_name;
    const identity = `archive-project-id:v1:기록원_${name}_PROJECT`;
    return { ...parsed.data, project_key: createHash("sha256").update(identity, "utf8").digest("hex") };
  }
  return parsed.data;
}
const READS = new Set<CreativeBridgeOperation>([
  "project_lore_writer_context", "project_lore_writer_render",
  "project_list", "project_context_read", "operation_result_read", "bridge_result_read", "project_provision_preview",
  "project_support_status", "project_session_status", "project_document_preview", "project_document_read", "project_lore_preview", "project_storage_status",
]);
export function isCreativeReadOperation(operation: CreativeBridgeOperation): boolean {
  return READS.has(operation);
}
const DESCRIPTIONS: Record<CreativeBridgeOperation, string> = {
  project_connect: "Connect an existing permitted canonical project by name and type from project_list under the host's explicit v4 delegation. project_key may be omitted. Reuses its designated worktree and existing support when current; first-time connection may create a linked worktree, Binding, support grant and relay membership. Does not create a project or open a session. Denied, revoked or uncertain state requires host recovery; never resubmit a timed-out mutation, read its original result.",
  project_lore_writer_context: "Get current approved stable-key value fields for creating or revising public project LORE. Read writer_request_json as data, and preserve its separate exact-byte request_sha256. Revise inherits summary/scope (send null); private LORE is forbidden. This does not open sessions, reserve IDs or save content.",
  project_lore_writer_render: "Return only complete stable-key values as writer_output_json for the original writer-context bridgeRequestId and request_sha256. The host validates current authority/preimage and renders canonical six artifacts. Use those exact artifacts in project_lore_prepare with an owned open session, then show the preview/card and obtain actual approval. Rendering does not save or approve content. On source drift request new context explicitly.",
  project_list: "List currently permitted projects and their enrollment state under the host's policy, including approved canonical names when general project entry is enabled. Listing does not grant access.",
  project_provision_preview: "Preview creation by project name and options under the host's explicit creation policy. project_key may be omitted and is derived before signing. Show the returned composite create/binding/support/enrollment card before relaying an explicit user decision.",
  project_provision_decide: "Relay the user's explicit decision on the exact original creation preview and composite effects. Does not initialize LORE storage or open a session.",
  project_support_status: "Read current enrolled project's support readiness; cannot grant or revoke support.",
  project_session_status: "Read current session state and the open-intent/active-set card for this conversation's audit correlation. Never adopt another conversation's session.",
  project_session_activate: "Request canonical session coordinator activation using the exact current status reference. Does not open, rebind, recover or take over a session.",
  project_session_open: "Open with the exact original status, open-intent digest and active-set digest. If the card requires parallel approval, relay the actual explicit user decision; never invent approval or adopt a sibling session.",
  project_session_close: "Close only the session proven by the original owned open operation, with the actual work summary.",
  project_document_prepare: "Prepare approved-candidate document content for the original owned open operation. Use current SHA256 or ABSENT. LORE requires its separate canonical manifest route; preparation alone does not save content.",
  project_document_preview: "Read the original document preparation and approval card. Show exact content/effects to the user before any decide request.",
  project_document_decide: "Relay an actual explicit user decision for the exact document card and original owned open operation. Only the protected result's verified postimage proves storage.",
  project_document_read: "Read current canonical document bytes/hash by semantic type and ID, including LORE through its manifest owner. Never accepts a filesystem path.",
  project_lore_prepare: "Prepare the six canonical manifest/renderer/writer-validated LORE artifacts under the original owned open operation. Arbitrary Markdown or invented validation receipts are invalid. Storage must already be ready.",
  project_lore_preview: "Read the original canonical LORE preparation/card before relaying a content decision.",
  project_lore_decide: "Relay the actual explicit decision on the original canonical LORE card and owned session. Native validation and verified source readback decide whether it was saved.",
  project_storage_status: "Read current LORE storage readiness. Creation alone does not initialize storage.",
  project_storage_prepare: "Prepare exact bounded LORE storage limits and display the returned effects/approval card. No storage initialization is performed by preparation.",
  project_storage_decide: "Relay the actual explicit user decision on the exact original storage-limits card.",
  project_context_read: "Read bounded current index/project/log/summary context from the enrolled project. Does not open/adopt sessions or save content.",
  operation_result_read: "Read an original owned relay operation's immutable native result using current permission. Never resend an operation or treat an unknown outcome as success.",
  bridge_result_read: "After a timeout, inquire about the same original bridgeRequestId using a fresh authenticated read. Never resubmit the original mutation; pending and recovery remain unresolved.",
};
export const CREATIVE_TOOLS: Tool[] = CREATIVE_OPERATIONS.map(operation => ({
  name: `archive_${operation}`, title: operation.replaceAll("_", " "), description: DESCRIPTIONS[operation],
  inputSchema: z.toJSONSchema(CREATIVE_SCHEMAS[operation], { target: "draft-7", io: "input" }) as Tool["inputSchema"],
  annotations: { readOnlyHint: isCreativeReadOperation(operation), destructiveHint: operation.endsWith("_decide"),
    idempotentHint: isCreativeReadOperation(operation), openWorldHint: false },
}));

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
function failedOwner(value: unknown): boolean {
  const owner = object(value);
  return owner?.schema_version === "aias-owner-result-projection-v1" && owner.terminal === true && owner.owner_status !== "PASS";
}
function pendingOwner(value: unknown): boolean {
  const owner = object(value);
  return owner?.schema_version === "aias-owner-result-projection-v1" && owner.terminal === false;
}
/** Inspect only known protocol fields, never status-like text inside document content. */
export function archiveResultDisposition(result: ArchiveBridgeSubmission): { isError: boolean; pending: boolean; inquiryTarget: string | null; nativePending: boolean } {
  let isError = result.state === "RECOVERY_REQUIRED" || failedOwner(result.ownerObservation);
  let nativePending = pendingOwner(result.ownerObservation);
  let pending = result.pending || result.state === "PENDING";
  let inquiryTarget = pending ? result.bridgeRequestId : null;
  const presentation = object(result.presentation);
  if (presentation?.schema_version === "aias-bridge-original-observation-v1") {
    isError ||= presentation.state === "RECOVERY_REQUIRED" || failedOwner(presentation.owner_observation);
    nativePending ||= pendingOwner(presentation.owner_observation);
    pending ||= presentation.state === "PENDING";
    if (pending && typeof presentation.target_bridge_request_id === "string" && UUID.test(presentation.target_bridge_request_id)) inquiryTarget = presentation.target_bridge_request_id;
    const originalRead = object(presentation.presentation);
    if (originalRead?.schema_version === "aias-bridge-read-presentation-v1" && originalRead.operation === "operation_result_read") {
      isError ||= failedOwner(originalRead.result);
      nativePending ||= pendingOwner(originalRead.result);
    }
  } else if (presentation?.schema_version === "aias-bridge-read-presentation-v1" && presentation.operation === "operation_result_read") {
    isError ||= failedOwner(presentation.result);
    nativePending ||= pendingOwner(presentation.result);
  }
  return { isError, pending: pending || nativePending, inquiryTarget, nativePending };
}
