import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const runtimeDir = path.dirname(fileURLToPath(import.meta.url));
export const repoDir = path.dirname(runtimeDir);
export const workspaceDir = path.dirname(repoDir);
export const burpUrl = process.env.CBH_BURP_URL || 'http://127.0.0.1:8181/mcp/sse';

export async function connect(entry, timeout = 15000) {
  const client = new Client({ name: 'cbh-runtime', version: '1.0.0' });
  const transport = entry.url
    ? new SSEClientTransport(new URL(entry.url))
    : new StdioClientTransport({ command: entry.command, args: entry.args || [],
        env: { ...process.env, ...entry.env }, cwd: entry.cwd || workspaceDir, stderr: 'pipe' });
  if (transport.stderr) transport.stderr.on('data', () => {});
  let timer;
  try {
    await Promise.race([
      client.connect(transport),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('MCP initialize timed out')), timeout); }),
    ]);
    return client;
  } catch (error) {
    await transport.close().catch(() => {});
    throw error;
  } finally { clearTimeout(timer); }
}

export async function listAllTools(client, timeout = 15000) {
  const tools = [];
  let cursor;
  const seen = new Set();
  do {
    const page = await client.listTools(cursor ? { cursor } : {}, { timeout });
    tools.push(...page.tools);
    cursor = page.nextCursor;
    if (cursor && seen.has(cursor)) throw new Error('MCP repeated tools/list cursor');
    if (cursor) seen.add(cursor);
    if (seen.size > 50) throw new Error('MCP tools/list pagination limit');
  } while (cursor);
  return tools;
}
