import { createHmac } from "node:crypto";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import { ArchiveBridgeClient, bridgeWaitMsForOperation, canonicalJson, type ArchiveBridgeSubmission } from "../src/gateway/archive-bridge-client.js";
import { ARCHIVE_TOOLS, callArchiveTool, isArchiveToolName } from "../src/gateway/archive-tools.js";
import { CREATIVE_OPERATIONS, CREATIVE_SCHEMAS, CREATIVE_TOOLS, archiveResultDisposition, isCreativeReadOperation, validateCreativeArguments, type CreativeBridgeOperation } from "../src/gateway/archive-creative-contract.js";

// Derived from the canonical Python owner's sample payloads; checked cross-language separately.
const fixtures: Record<string, any> = {
  project_connect: { project_key: "demo", payload: { context: {
    conversation_correlation: "app-session-one", user_message: "이 기존 프로젝트 연결해 주세요", message_reference: null },
    project_name: "원격검증", project_type: "testbed" } },
  "project_document_decide": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_operation_id": "20000000-0000-4000-8000-000000000002",
      "decision": {
        "binding_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "decision_id": "40000000-0000-4000-8000-000000000004",
        "decision": "approved",
        "user_message": "이 내용 저장 승인",
        "message_reference": null,
        "decided_at": "2026-10-09T00:00:00Z",
        "expires_at": "2026-10-09T00:30:00Z"
      },
      "target_open_operation_id": "30000000-0000-4000-8000-000000000003"
    }
  },
  "project_document_prepare": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_open_operation_id": "30000000-0000-4000-8000-000000000003",
      "document": {
        "document_type": "MEMO",
        "document_id": "기록원_원격검증_MEMO_작업",
        "area": "project",
        "category": "",
        "content": "# 작업 메모\n저장할 본문\n",
        "expected_sha256": "ABSENT"
      }
    }
  },
  "project_document_preview": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_operation_id": "20000000-0000-4000-8000-000000000002"
    }
  },
  "project_document_read": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "document": {
        "document_type": "MEMO",
        "document_id": "기록원_원격검증_MEMO_작업",
        "area": "project",
        "category": ""
      }
    }
  },
  "project_lore_decide": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_operation_id": "20000000-0000-4000-8000-000000000002",
      "decision": {
        "binding_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "decision_id": "40000000-0000-4000-8000-000000000004",
        "decision": "approved",
        "user_message": "이 내용 저장 승인",
        "message_reference": null,
        "decided_at": "2026-10-09T00:00:00Z",
        "expires_at": "2026-10-09T00:30:00Z"
      },
      "target_open_operation_id": "30000000-0000-4000-8000-000000000003"
    }
  },
  "project_lore_prepare": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_open_operation_id": "30000000-0000-4000-8000-000000000003",
      "artifacts": {
        "rendered_lore.md": "{}",
        "accountability_ledger.json": "{}",
        "manifest.json": "{}",
        "validation_receipt.json": "{}",
        "raw_inventory.json": "{}",
        "value_payload.json": "{}"
      }
    }
  },
  "project_lore_preview": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_operation_id": "20000000-0000-4000-8000-000000000002"
    }
  },
  "project_provision_decide": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_operation_id": "20000000-0000-4000-8000-000000000002",
      "decision": {
        "binding_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "decision_id": "40000000-0000-4000-8000-000000000004",
        "decision": "approved",
        "user_message": "이 내용 저장 승인",
        "message_reference": null,
        "decided_at": "2026-10-09T00:00:00Z",
        "expires_at": "2026-10-09T00:30:00Z"
      }
    }
  },
  "project_provision_preview": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "project": {
        "project_name": "원격검증",
        "project_type": "testbed",
        "toolboxes": [],
        "include_world_summary": true,
        "include_memo": true,
        "branching": false
      }
    }
  },
  "project_session_activate": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_state_operation_id": "20000000-0000-4000-8000-000000000002"
    }
  },
  "project_session_close": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_open_operation_id": "30000000-0000-4000-8000-000000000003",
      "summary": "오늘의 작업 저장 완료"
    }
  },
  "project_session_open": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_state_operation_id": "20000000-0000-4000-8000-000000000002",
      "open_intent_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "observed_active_sessions_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "parallel_decision": null
    }
  },
  "project_session_status": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      }
    }
  },
  "project_storage_decide": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "target_operation_id": "20000000-0000-4000-8000-000000000002",
      "decision": {
        "binding_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "decision_id": "40000000-0000-4000-8000-000000000004",
        "decision": "approved",
        "user_message": "이 내용 저장 승인",
        "message_reference": null,
        "decided_at": "2026-10-09T00:00:00Z",
        "expires_at": "2026-10-09T00:30:00Z"
      }
    }
  },
  "project_storage_prepare": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      },
      "limits": {
        "max_hot_bytes": 1024,
        "max_total_bytes": 4096,
        "warning_threshold_bytes": 512,
        "required_recovery_headroom_bytes": 256
      }
    }
  },
  "project_storage_status": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      }
    }
  },
  "project_support_status": {
    "project_key": "demo",
    "payload": {
      "context": {
        "conversation_correlation": "app-session-one",
        "user_message": "저장해 주세요",
        "message_reference": null
      }
    }
  },
  "project_list": {},
  "project_context_read": {
    "project_key": "demo",
    "scopes": [
      "index",
      "project"
    ],
    "max_bytes_per_document": 4096
  },
  "operation_result_read": {
    "target_operation_id": "20000000-0000-4000-8000-000000000002"
  },
  "bridge_result_read": {
    "target_bridge_request_id": "20000000-0000-4000-8000-000000000002"
  }
};
const UUID = "20000000-0000-4000-8000-000000000002";
const QUERY = "30000000-0000-4000-8000-000000000003";
const baseResult: ArchiveBridgeSubmission = { bridgeRequestId: QUERY, state: "RESULT_OBSERVED", reasonCode: "BRIDGE_READ_OBSERVED",
  relayOperationId: null, ownerObservation: null, presentation: null, automaticResubmissionAllowed: false,
  createdAt: 1, pending: false };

const writerAudit = { conversation_correlation: "writer-fixture", user_message: "Write a public LORE draft", message_reference: null };
fixtures.project_lore_writer_context = { project_key: "demo", payload: {
  context: writerAudit, intent: "create", toolbox_id: "worldbuilding", compass_id: "도구상자_세계관_나침반_02_존재론과법칙",
  category: "세계관", title: "존재와법칙", source_id: null, brief: "A synthetic mechanics fixture", summary: "",
  scope: { Definitiveness: "exploratory", Expression: { Typicality: 50, Depth: 50 } }, change_keys: [], status: "draft",
} };
const writerOutput = { schema_version: "lore-writer-production-response-v1", request_sha256: "a".repeat(64),
  values: { subject_id: "기록원_테스트_LORE_세계관_001_존재와법칙", status: "draft", fields: { example: {
    state: "set", value: { "10": 0.000001, "2": "두 번째" }, reason: null, revisit_condition: null, evidence: [], confidence: 0.5,
  } } } };
fixtures.project_lore_writer_render = { project_key: "demo", payload: { context: writerAudit,
  target_bridge_request_id: "20000000-0000-4000-8000-000000000002", request_sha256: "a".repeat(64),
  writer_reference: "synthetic-mechanics-only", writer_output_json: JSON.stringify(writerOutput),
} };

function clone(value: any): any { return structuredClone(value); }
function owner(status: string): Record<string, unknown> {
  return { schema_version: "aias-owner-result-projection-v1", terminal: true, owner_status: status };
}

describe("closed creative Archive tools", () => {
  it.each([
    ["원격검증", "09ad99ce28ef37c16720bef1a0a0e16ce03c23b3ed8d3424c32085cc2474d72c"],
    ["새 세계", "3cabda7d21d9cd87141396ea010bec73d077cbe79f9c6d296a333f00f6613aba"],
    ["범용생성20261012", "70127ab9d1ff8f10617b9c40bd131477ce6405086aee8a565696c2790bfe8bde"],
  ])("derives omitted creation key for %s before signing", (name, key) => {
    const raw = clone(fixtures.project_provision_preview);
    delete raw.project_key;
    raw.payload.project.project_name = name;
    const parsed = validateCreativeArguments("project_provision_preview", raw);
    expect(parsed.project_key).toBe(key);
    expect(raw.project_key).toBeUndefined();
    expect(parsed.payload).toEqual(raw.payload);
    const schema = CREATIVE_TOOLS.find(tool => tool.name === "archive_project_provision_preview")!.inputSchema;
    expect(schema.required).not.toContain("project_key");
    expect(schema.required).toContain("payload");
  });
  it.each([
    ["원격검증", "09ad99ce28ef37c16720bef1a0a0e16ce03c23b3ed8d3424c32085cc2474d72c"],
    ["새 세계", "3cabda7d21d9cd87141396ea010bec73d077cbe79f9c6d296a333f00f6613aba"],
  ])("derives omitted existing connection key for %s", (name, key) => {
    const raw = clone(fixtures.project_connect);
    delete raw.project_key;
    raw.payload.project_name = name;
    const parsed = validateCreativeArguments("project_connect", raw);
    expect(parsed.project_key).toBe(key);
    expect(parsed.payload).toEqual(raw.payload);
    expect(raw.project_key).toBeUndefined();
    const tool = CREATIVE_TOOLS.find(item => item.name === "archive_project_connect")!;
    expect(tool.inputSchema.required).not.toContain("project_key");
    expect(tool.annotations?.readOnlyHint).toBe(false);
  });
  it("lists precisely 24 creative and three legacy tools without adding generic backend tools", () => {
    expect(CREATIVE_OPERATIONS).toHaveLength(24);
    expect(ARCHIVE_TOOLS).toHaveLength(27);
    expect(new Set(ARCHIVE_TOOLS.map(tool => tool.name)).size).toBe(27);
    for (const tool of CREATIVE_TOOLS) {
      expect(isArchiveToolName(tool.name)).toBe(true);
      expect(tool.inputSchema.type).toBe("object");
      expect(tool.inputSchema.additionalProperties).toBe(false);
      expect(tool.annotations?.openWorldHint).toBe(false);
      expect(tool.description).toBeTruthy();
    }
    expect(isArchiveToolName("archive_native_execute")).toBe(false);
    expect(isArchiveToolName("archive___proto__")).toBe(false);
  });
  it("keeps mutation wait separate from read and inquiry waits", () => {
    const waits = { bridgeResultWaitMs: 30000, bridgeReadWaitMs: 2000, bridgeResultReadWaitMs: 250 };
    expect(bridgeWaitMsForOperation(waits, "project_list")).toBe(2000);
    expect(bridgeWaitMsForOperation(waits, "project_document_read")).toBe(2000);
    expect(bridgeWaitMsForOperation(waits, "bridge_result_read")).toBe(250);
    expect(bridgeWaitMsForOperation(waits, "project_document_prepare")).toBe(30000);
    expect(bridgeWaitMsForOperation(waits, "project_document_decide")).toBe(30000);
    expect(bridgeWaitMsForOperation(waits, "source_draft_decide")).toBe(30000);
  });

  it("classifies only declared creative reads for the shorter gateway wait", () => {
    expect(isCreativeReadOperation("project_list")).toBe(true);
    expect(isCreativeReadOperation("project_context_read")).toBe(true);
    expect(isCreativeReadOperation("project_document_read")).toBe(true);
    expect(isCreativeReadOperation("bridge_result_read")).toBe(true);
    expect(isCreativeReadOperation("project_document_prepare")).toBe(false);
    expect(isCreativeReadOperation("project_document_decide")).toBe(false);
  });

  it.each(CREATIVE_OPERATIONS)("preserves canonical %s semantic payload", operation => {
    const result = validateCreativeArguments(operation, fixtures[operation]);
    expect(result).toEqual(fixtures[operation]);
  });
  it.each(CREATIVE_OPERATIONS)("rejects injected authority before submitting %s", async operation => {
    const submit = vi.fn();
    const client = { submit } as unknown as ArchiveBridgeClient;
    await expect(callArchiveTool(client, `archive_${operation}`, { ...fixtures[operation], native_action: "execute" }, undefined)).rejects.toThrow();
    expect(submit).not.toHaveBeenCalled();
    const nested = clone(fixtures[operation]);
    if (nested.payload) {
      nested.payload.context.independent_human_authentication = true;
      expect(() => validateCreativeArguments(operation, nested)).toThrow();
    }
  });
  it("requires real booleans/integers and complete closed nested schemas", () => {
    const project = clone(fixtures.project_provision_preview);
    project.payload.project.include_memo = 1;
    expect(() => validateCreativeArguments("project_provision_preview", project)).toThrow();
    const storage = clone(fixtures.project_storage_prepare);
    storage.payload.limits.max_hot_bytes = true;
    expect(() => validateCreativeArguments("project_storage_prepare", storage)).toThrow();
    storage.payload.limits.max_hot_bytes = 1.2;
    expect(() => validateCreativeArguments("project_storage_prepare", storage)).toThrow();
    const context = clone(fixtures.project_context_read);
    context.scopes = ["index", "index"];
    expect(() => validateCreativeArguments("project_context_read", context)).toThrow();
    const lore = clone(fixtures.project_lore_prepare);
    delete lore.payload.artifacts["validation_receipt.json"];
    expect(() => validateCreativeArguments("project_lore_prepare", lore)).toThrow();
    const document = clone(fixtures.project_document_prepare);
    document.payload.document.document_type = "LORE";
    expect(() => validateCreativeArguments("project_document_prepare", document)).toThrow();
  });
  it.each(["a/b", "a\\b", "..", "CON.txt", "trailing.", " bad", "a\0b", "a\nb"])("rejects document component %j", name => {
    const input = clone(fixtures.project_document_prepare);
    input.payload.document.document_id = name;
    expect(() => validateCreativeArguments("project_document_prepare", input)).toThrow();
  });
  it("accepts ordinary ASCII names without overbroad path rejection", () => {
    const input = clone(fixtures.project_document_prepare);
    input.payload.document.document_id = "example_xyz_012345";
    expect(validateCreativeArguments("project_document_prepare", input)).toEqual(input);
  });
  it.each(["\ud800", "\udfff", "x\ud800y"])("rejects lone UTF16 surrogate %j", invalid => {
    const input = clone(fixtures.project_session_status);
    input.payload.context.user_message = invalid;
    expect(() => validateCreativeArguments("project_session_status", input)).toThrow();
    const content = clone(fixtures.project_document_prepare);
    content.payload.document.content = invalid;
    expect(() => validateCreativeArguments("project_document_prepare", content)).toThrow();
  });
  it("enforces actual UTF8 byte bounds without changing valid non-BMP content", () => {
    const input = clone(fixtures.project_session_status);
    input.payload.context.user_message = "가".repeat(1365) + "x";
    expect(validateCreativeArguments("project_session_status", input)).toEqual(input);
    input.payload.context.user_message += "x";
    expect(() => validateCreativeArguments("project_session_status", input)).toThrow();
    input.payload.context.user_message = "🦉".repeat(1024);
    expect(validateCreativeArguments("project_session_status", input)).toEqual(input);
    input.payload.context.user_message += "x";
    expect(() => validateCreativeArguments("project_session_status", input)).toThrow();
  });
  it("bounds the complete six-artifact payload, not only each component", () => {
    const input = clone(fixtures.project_lore_prepare);
    for (const key of Object.keys(input.payload.artifacts)) input.payload.artifacts[key] = "x".repeat(1024 * 1024);
    expect(() => validateCreativeArguments("project_lore_prepare", input)).toThrow();
  });
  it("preserves decision identity/time evidence and rejects invalid order/parallel expiry", async () => {
    const submit = vi.fn().mockResolvedValue(baseResult);
    const client = { submit } as unknown as ArchiveBridgeClient;
    await callArchiveTool(client, "archive_project_document_decide", fixtures.project_document_decide, undefined);
    expect(submit).toHaveBeenCalledWith("project_document_decide", fixtures.project_document_decide, undefined);
    const bad = clone(fixtures.project_document_decide);
    bad.payload.decision.expires_at = bad.payload.decision.decided_at;
    expect(() => validateCreativeArguments("project_document_decide", bad)).toThrow();
    bad.payload.decision.expires_at = "2026-02-30T00:00:00Z";
    expect(() => validateCreativeArguments("project_document_decide", bad)).toThrow();
    const parallel = clone(fixtures.project_session_open);
    parallel.payload.parallel_decision = { decision: clone(fixtures.project_document_decide.payload.decision), previous_decision_sha256: null };
    parallel.payload.parallel_decision.decision.expires_at = "2026-10-09T01:00:00Z";
    expect(() => validateCreativeArguments("project_session_open", parallel)).toThrow();
  });
  it("keeps the legacy false parallel flag instead of manufacturing an approval", async () => {
    const submit = vi.fn().mockResolvedValue(baseResult);
    const semantic = { target_operation_id: UUID, ...fixtures.project_document_decide.payload.decision, parallel_session_approved: false };
    await callArchiveTool({ submit } as unknown as ArchiveBridgeClient, "archive_source_draft_decide", semantic, undefined);
    expect(submit).toHaveBeenCalledWith("source_draft_decide", semantic, undefined);
  });
  it.each(["BLOCKED_OPERATION", "RECOVERY_REQUIRED", "INTERNAL_ERROR"])("preserves native refusal %s across protocol wrappers", status => {
    const projection = owner(status);
    expect(archiveResultDisposition({ ...baseResult, ownerObservation: projection }).isError).toBe(true);
    expect(archiveResultDisposition({ ...baseResult, presentation: { schema_version: "aias-bridge-read-presentation-v1", operation: "operation_result_read", result: projection } }).isError).toBe(true);
    expect(archiveResultDisposition({ ...baseResult, presentation: { schema_version: "aias-bridge-original-observation-v1", state: "RESULT_OBSERVED", owner_observation: projection } }).isError).toBe(true);
  });
  it("nested pending points only to the original bridge ID and keeps the result intact", async () => {
    const result = { ...baseResult, presentation: { schema_version: "aias-bridge-original-observation-v1", target_bridge_request_id: UUID,
      state: "PENDING", owner_observation: null, presentation: null, source_saved: false } };
    const submit = vi.fn().mockResolvedValue(result);
    const output = await callArchiveTool({ submit } as unknown as ArchiveBridgeClient, "archive_bridge_result_read", { target_bridge_request_id: UUID }, undefined);
    expect(output.isError).toBe(false);
    expect(output.structuredContent).toMatchObject({ pending: true, presentation: result.presentation,
      nextAction: { tool: "archive_bridge_result_read", arguments: { target_bridge_request_id: UUID } } });
    expect(submit).toHaveBeenCalledTimes(1);
    expect(archiveResultDisposition({ ...result, presentation: { ...result.presentation, state: "RECOVERY_REQUIRED" } }).isError).toBe(true);
  });
  it("does not inspect document content for status-like fields", () => {
    expect(archiveResultDisposition({ ...baseResult, ownerObservation: owner("PASS"), presentation: { content: owner("INTERNAL_ERROR") } }).isError).toBe(false);
  });
});

describe("attested v2 publication", () => {
  async function clientFixture() {
    // Retained bounded external test output: no production OAuth or directories used.
    const root = await mkdtemp(path.join(os.tmpdir(), "aias-gateway-creative-test-"));
    const exchange = path.join(root, "exchange");
    const keyFile = path.join(root, "fixture.key");
    await writeFile(keyFile, "k".repeat(64), "utf8");
    const base = "https://example.test";
    const config = loadConfig({ MCP_MODE: "gateway", MCP_OAUTH_ENABLED: "true", MCP_OAUTH_APPROVAL_KEY: "public-fixture-approval",
      MCP_PUBLIC_URL: base, MCP_GENERIC_BACKEND_URL: "http://127.0.0.1:19999/mcp", MCP_BRIDGE_EXCHANGE_ROOT: exchange,
      MCP_BRIDGE_ATTESTATION_KEY_FILE: keyFile, MCP_BRIDGE_GENERATION: "7", MCP_GATEWAY_SOURCE_FINGERPRINT: "a".repeat(64), MCP_BRIDGE_RESULT_WAIT_MS: "0" }, root);
    const auth: AuthInfo = { token: "public-fixture-raw-oauth-must-not-appear", clientId: "fixture-client", scopes: ["mcp:tools"], expiresAt: Math.floor(Date.now() / 1000) + 600, resource: new URL(`${base}/mcp`) };
    return { root, exchange, auth, client: new ArchiveBridgeClient(config) };
  }
  it("uses v2 only for the closed creative operations and keeps decision bytes unchanged", async () => {
    const { client, exchange, auth } = await clientFixture();
    for (const operation of CREATIVE_OPERATIONS) {
      const result = await client.submit(operation, fixtures[operation], auth);
      expect(result.pending).toBe(true);
      const raw = await readFile(path.join(exchange, "requests", `${result.bridgeRequestId}.json`), "utf8");
      expect(raw).not.toContain(auth.token);
      const parsed = JSON.parse(raw);
      expect(parsed.schema_version).toBe("aias-receiving-host-bridge-request-v2");
      expect(parsed.semantic_payload).toEqual(fixtures[operation]);
      expect(parsed.bridge_request_id).toBe(result.bridgeRequestId);
      const { mac_sha256: mac, ...unsigned } = parsed;
      expect(mac).toBe(createHmac("sha256", "k".repeat(64)).update(canonicalJson(unsigned), "utf8").digest("hex"));
    }
    expect(await readdir(path.join(exchange, "requests"))).toHaveLength(24);
  });
  it.each(["project_connect", "project_provision_preview"] as const)("signs omitted-key %s only after canonical key derivation", async operation => {
    const { client, exchange, auth } = await clientFixture();
    const raw = clone(fixtures[operation]);
    delete raw.project_key;
    const parsed = validateCreativeArguments(operation, raw);
    const result = await callArchiveTool(client, `archive_${operation}`, raw, auth);
    const structured = result.structuredContent as Record<string, unknown>;
    const request = JSON.parse(await readFile(path.join(exchange, "requests", `${structured.bridgeRequestId}.json`), "utf8"));
    expect(request.semantic_payload).toEqual(parsed);
    expect(request.semantic_payload.project_key).toBe("09ad99ce28ef37c16720bef1a0a0e16ce03c23b3ed8d3424c32085cc2474d72c");
    const { mac_sha256: mac, ...unsigned } = request;
    expect(mac).toBe(createHmac("sha256", "k".repeat(64)).update(canonicalJson(unsigned), "utf8").digest("hex"));
    expect(raw.project_key).toBeUndefined();
    expect(await readdir(path.join(exchange, "requests"))).toHaveLength(1);
  });
  it("rejects unknown operation, invalid semantics and missing OAuth before writing any request", async () => {
    const { client, root, exchange, auth } = await clientFixture();
    await expect(client.submit("native_execute" as CreativeBridgeOperation, {}, auth)).rejects.toThrow();
    await expect(client.submit("project_list", { path: "C:/" }, auth)).rejects.toThrow();
    await expect(client.submit("project_list", {}, undefined)).rejects.toThrow();
    expect(await readdir(root)).not.toContain(path.basename(exchange));
  });
});


it("a pending native result uses a fresh read of its original target, never a frozen read-result poll", async () => {
  const projection = { ...owner("PENDING"), terminal: false };
  const result = { ...baseResult, presentation: { schema_version: "aias-bridge-read-presentation-v1", operation: "operation_result_read", result: projection } };
  const submit = vi.fn().mockResolvedValue(result);
  const output = await callArchiveTool({ submit } as unknown as ArchiveBridgeClient, "archive_operation_result_read", { target_operation_id: UUID }, undefined);
  expect(output.isError).toBe(false);
  expect(output.structuredContent).toMatchObject({ pending: true, nextAction: { tool: "archive_operation_result_read", arguments: { target_operation_id: UUID } } });
  expect(archiveResultDisposition({ ...baseResult, presentation: { schema_version: "aias-bridge-original-observation-v1", state: "RESULT_OBSERVED", presentation: result.presentation } })).toMatchObject({ pending: true, nativePending: true, inquiryTarget: null });
});


it.each(["\n", "\r\n", " "])("rejects trailing data after an apparently valid reference or selector: %j", suffix => {
  expect(() => validateCreativeArguments("operation_result_read", { target_operation_id: UUID + suffix })).toThrow();
  const selected = clone(fixtures.project_session_status);
  selected.project_key += suffix;
  expect(() => validateCreativeArguments("project_session_status", selected)).toThrow();
  const decided = clone(fixtures.project_document_decide);
  decided.payload.decision.binding_sha256 += suffix;
  expect(() => validateCreativeArguments("project_document_decide", decided)).toThrow();
});

describe("writer JSON and revision boundary", () => {
  it("preserves whitespace, numeric keys and floating-point spelling exactly", () => {
    const input = clone(fixtures.project_lore_writer_render);
    input.payload.writer_output_json = JSON.stringify(writerOutput, null, 2).replace("0.000001", "1e-6");
    expect(validateCreativeArguments("project_lore_writer_render", input)).toEqual(input);
  });
  it.each([
    ["duplicate field", (raw: string) => raw.replace('"status":"draft"', '"status":"draft","status":"confirmed"')],
    ["escaped duplicate", (raw: string) => raw.replace('"status":"draft"', '"status":"draft","sta\\u0074us":"draft"')],
    ["nonfinite", (raw: string) => raw.replace('"confidence":0.5', '"confidence":1e999')],
    ["oversized integer", (raw: string) => raw.replace('"confidence":0.5', '"confidence":9007199254740992')],
    ["unpaired surrogate", (raw: string) => raw.replace('"reason":null', '"reason":"\\ud800"')],
    ["NUL", (raw: string) => raw.replace('"reason":null', '"reason":"\\u0000"')],
    ["unknown key", (raw: string) => raw.replace('"values":', '"metadata":{},"values":')],
  ])("rejects %s before publication", (_name, mutate) => {
    const input = clone(fixtures.project_lore_writer_render);
    input.payload.writer_output_json = mutate(input.payload.writer_output_json);
    expect(() => validateCreativeArguments("project_lore_writer_render", input)).toThrow();
  });
  it("requires explicit baseline inheritance for revisions", () => {
    const input = clone(fixtures.project_lore_writer_context);
    Object.assign(input.payload, { intent: "revise", toolbox_id: null, compass_id: null, category: null, title: null,
      source_id: "기록원_테스트_LORE_세계관_001_존재와법칙", summary: null, scope: null, change_keys: ["example"] });
    expect(validateCreativeArguments("project_lore_writer_context", input)).toEqual(input);
    input.payload.summary = "";
    expect(() => validateCreativeArguments("project_lore_writer_context", input)).toThrow();
  });
  it("rejects graph depth and changed response hash", () => {
    const input = clone(fixtures.project_lore_writer_render);
    const output = clone(writerOutput);
    let value: unknown = "leaf";
    for (let i = 0; i < 25; i++) value = [value];
    output.values.fields.example.value = value;
    input.payload.writer_output_json = JSON.stringify(output);
    expect(() => validateCreativeArguments("project_lore_writer_render", input)).toThrow();
    input.payload.writer_output_json = JSON.stringify(writerOutput);
    input.payload.request_sha256 = "b".repeat(64);
    expect(() => validateCreativeArguments("project_lore_writer_render", input)).toThrow();
  });
});
