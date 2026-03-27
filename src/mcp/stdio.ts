import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "../config/index.js";
import { TerminalManager } from "../terminal/index.js";
import { createSshTransportFactory } from "../transport/index.js";
import { createMcpServer } from "./server.js";

const config = loadConfig();
const transportFactory = createSshTransportFactory(config);
const terminalManager = new TerminalManager(config, transportFactory);

const mcpServer = createMcpServer(config, terminalManager);
const transport = new StdioServerTransport();

await mcpServer.connect(transport);
