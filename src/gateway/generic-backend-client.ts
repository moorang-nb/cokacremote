import { randomUUID } from "node:crypto";

import {
  CallToolResultSchema,
  ErrorCode,
  ListToolsResultSchema,
  McpError,
  type CallToolResult,
  type ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";

interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

interface JsonRpcResponse {
  jsonrpc?: unknown;
  id?: unknown;
  result?: unknown;
  error?: unknown;
}

function parseError(value: unknown): JsonRpcError | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const code = (value as { code?: unknown }).code;
  const message = (value as { message?: unknown }).message;
  if (typeof code !== "number" || !Number.isInteger(code) || typeof message !== "string") {
    return undefined;
  }
  return { code, message, data: (value as { data?: unknown }).data };
}

export class GenericBackendClient {
  constructor(private readonly endpoint: URL) {}

  private async request(method: string, params: Record<string, unknown>): Promise<unknown> {
    const id = randomUUID();
    let response: Response;
    try {
      response = await fetch(this.endpoint, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method,
          params,
        }),
      });
    } catch {
      throw new McpError(ErrorCode.InternalError, "Generic backend unavailable");
    }

    if (!response.ok) {
      throw new McpError(
        ErrorCode.InternalError,
        `Generic backend HTTP failure: ${response.status}`,
      );
    }

    let payload: JsonRpcResponse;
    try {
      payload = (await response.json()) as JsonRpcResponse;
    } catch {
      throw new McpError(ErrorCode.InternalError, "Generic backend returned invalid JSON");
    }
    if (payload.jsonrpc !== "2.0" || payload.id !== id) {
      throw new McpError(ErrorCode.InternalError, "Generic backend JSON-RPC identity mismatch");
    }
    const backendError = parseError(payload.error);
    if (backendError) {
      throw new McpError(backendError.code, backendError.message, backendError.data);
    }
    if (!("result" in payload)) {
      throw new McpError(ErrorCode.InternalError, "Generic backend response missing result");
    }
    return payload.result;
  }

  async listTools(params: Record<string, unknown> = {}): Promise<ListToolsResult> {
    const parsed = ListToolsResultSchema.safeParse(await this.request("tools/list", params));
    if (!parsed.success) {
      throw new McpError(ErrorCode.InternalError, "Generic backend returned invalid tools/list");
    }
    return parsed.data;
  }

  async callTool(params: Record<string, unknown>): Promise<CallToolResult> {
    const parsed = CallToolResultSchema.safeParse(
      await this.request("tools/call", params),
    );
    if (!parsed.success) {
      throw new McpError(ErrorCode.InternalError, "Generic backend returned invalid tools/call");
    }
    return parsed.data;
  }
}
