import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";

import type { AppConfig } from "./config.js";
import { registerExecTools } from "./exec-tools.js";
import { FileService } from "./file-service.js";
import { registerFileTools } from "./file-tools.js";
import {
  ARCHIVE_TOOLS,
  callArchiveTool,
  isArchiveToolName,
} from "./gateway/archive-tools.js";
import { ArchiveBridgeClient } from "./gateway/archive-bridge-client.js";
import { GenericBackendClient } from "./gateway/generic-backend-client.js";
import { ProcessManager } from "./process-manager.js";
import { toolAuthMetadata } from "./tool-metadata.js";

export interface McpServices {
  processManager: ProcessManager;
  fileService: FileService;
}

export type ManagedMcpServer = McpServer | Server;

export function createServices(config: AppConfig): McpServices {
  return {
    processManager: new ProcessManager({
      maxRetainedOutputBytes: config.maxRetainedProcessOutputBytes,
      processRetentionMs: config.processRetentionMs,
      maxProcesses: config.maxProcesses,
      defaultMaxOutputBytes: config.maxOutputBytes,
    }),
    fileService: new FileService({
      defaultCwd: config.defaultCwd,
      maxChunkBytes: config.maxFileChunkBytes,
      maxEditFileBytes: config.maxEditFileBytes,
      maxOutputBytes: config.maxOutputBytes,
    }),
  };
}

function createGenericMcpServer(
  config: AppConfig,
  services: McpServices | undefined,
): McpServer {
  if (!services) {
    throw new Error("Generic MCP mode requires local services");
  }
  const privateBackend = config.mode === "generic-backend";
  const server = new McpServer(
    {
      name: privateBackend ? "cokacremote-generic-backend" : "cokacremote",
      version: "0.1.0",
    },
    {
      instructions: privateBackend
        ? "Private generic execution backend. This process is not a public authentication or Archive authority."
        : "This server is an unrestricted remote development environment. Tools operate directly on the host with the MCP service process's full OS permissions. Use exec_command for shell, build, test, package, Git, service, and log workflows; run_script for complete Bash, Node.js, or Python scripts; and the file tools for direct file operations. Poll long-running commands with read_process or write_stdin.",
      capabilities: { logging: {} },
    },
  );

  registerExecTools(
    server,
    config,
    services.processManager,
    services.fileService,
  );
  registerFileTools(server, config, services.fileService);
  return server;
}

function createGatewayMcpServer(config: AppConfig): Server {
  if (!config.genericBackendUrl) {
    throw new Error("Gateway mode requires a generic backend URL");
  }
  const generic = new GenericBackendClient(new URL(config.genericBackendUrl));
  const archive = new ArchiveBridgeClient(config);
  const archiveNames = new Set(ARCHIVE_TOOLS.map((tool) => tool.name));
  const publicAuthMetadata = toolAuthMetadata(config);
  const exposePublicAuth = <T extends { _meta?: Record<string, unknown> }>(
    tool: T,
  ): T =>
    publicAuthMetadata
      ? ({
          ...tool,
          _meta: {
            ...(tool._meta ?? {}),
            ...publicAuthMetadata,
          },
        } as T)
      : tool;

  const server = new Server(
    {
      name: "cokacremote-gateway",
      version: "0.1.0",
    },
    {
      capabilities: {
        logging: {},
        tools: {},
      },
      instructions:
        "Public authenticated MCP gateway. Generic development tools are proxied to a private backend; Archive source tools use a separate verified bridge and do not expose filesystem or relay authority.",
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    const backend = await generic.listTools(
      request.params ? { ...request.params } : {},
    );
    const duplicate = backend.tools.find((tool) => archiveNames.has(tool.name));
    if (duplicate) {
      throw new McpError(
        ErrorCode.InternalError,
        `Generic backend conflicts with reserved Archive tool: ${duplicate.name}`,
      );
    }
    const publicBackendTools = backend.tools.map(exposePublicAuth);
    const cursor = request.params?.cursor;
    if (cursor) {
      return {
        ...backend,
        tools: publicBackendTools,
      };
    }
    return {
      ...backend,
      tools: [
        ...publicBackendTools,
        ...ARCHIVE_TOOLS.map(exposePublicAuth),
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const name = request.params.name;
    if (isArchiveToolName(name)) {
      return await callArchiveTool(
        archive,
        name,
        request.params.arguments,
        extra.authInfo,
      );
    }
    return await generic.callTool({ ...request.params });
  });

  return server;
}

export function createMcpServer(
  config: AppConfig,
  services?: McpServices,
): ManagedMcpServer {
  if (config.mode === "gateway") {
    return createGatewayMcpServer(config);
  }
  return createGenericMcpServer(config, services);
}
