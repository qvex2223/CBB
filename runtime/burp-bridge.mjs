// Keep the Claude-facing stdio connection alive while the GUI/SSE backend recovers.
// Discovery may reconnect; an ambiguous tools/call is NEVER replayed automatically.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'node:child_process';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { burpUrl, connect, listAllTools, repoDir, runtimeDir } from './client.mjs';

export class Backend {
  constructor({ connector = () => connect({ url: burpUrl }, 5000),
                starter = startBurp, logger = () => {} } = {}) {
    this.connector = connector; this.starter = starter; this.logger = logger;
    this.client = null; this.pending = null; this.nextStart = 0; this.closed = false;
  }
  async ensure() {
    if (this.closed) throw new Error('Burp bridge closed');
    if (this.client) return this.client;
    if (this.pending) return this.pending;
    this.pending = this.open().finally(() => { this.pending = null; });
    return this.pending;
  }
  async open() {
    let client;
    try { client = await this.connector(); }
    catch (error) {
      if (Date.now() < this.nextStart) throw error;
      this.nextStart = Date.now() + 180000;
      this.logger('backend unavailable; starting local Burp');
      await this.starter();
      client = await this.connector();
    }
    if (this.closed) { await client.close(); throw new Error('Burp bridge closed'); }
    client.onclose = () => { if (this.client === client) this.client = null; };
    this.client = client;
    return client;
  }
  async invalidate(client) {
    if (this.client === client) this.client = null;
    await client?.close().catch(() => {});
  }
  async call(params) {
    const client = await this.ensure();
    try { return await client.callTool(params, undefined, { timeout: 90000 }); }
    catch (error) {
      await this.invalidate(client);
      throw new Error('Burp connection failed; the action may have executed and was NOT replayed. '
        + 'Inspect HTTP history/state before retrying. ' + error.message);
    }
  }
  async close() { this.closed = true; await this.invalidate(this.client); }
}

async function startBurp() {
  const url = new URL(burpUrl);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))
    throw new Error('Remote Burp is unavailable; automatic local startup is not applicable');
  await new Promise((resolve, reject) => {
    const child = spawn('bash', [path.join(repoDir, 'scripts/burp-mcp.sh'), 'start'], {
      stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, BURP_MCP_PORT: url.port || '8181' },
    });
    child.stderr.on('data', data => process.stderr.write(data));
    const timer = setTimeout(() => { child.kill('SIGTERM'); reject(new Error('Burp startup timed out')); }, 180000);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('exit', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error(`Burp startup failed (${code}); run cbh tools doctor --start`)); });
  });
}

async function main() {
  const backend = new Backend({ logger: text => process.stderr.write(`cbh-burp: ${text}\n`) });
  const server = new Server({ name: 'cbh-burpmcp', version: '1.0.0' }, { capabilities: { tools: {} } });
  const cache = path.join(runtimeDir, 'state/burp-tools.json');
  let tools = [];
  try { const saved = JSON.parse(await readFile(cache, 'utf8')); if (saved.url === burpUrl) tools = saved.tools; } catch {}
  let refreshing;
  const refresh = () => refreshing ||= (async () => {
    const client = await backend.ensure();
    try {
      const discovered = await listAllTools(client);
      if (!discovered.length) throw new Error('Burp advertised no tools');
      tools = discovered;
      await mkdir(path.dirname(cache), { recursive: true });
      const temp = `${cache}.${process.pid}.tmp`;
      await writeFile(temp, JSON.stringify({ url: burpUrl, checked_at: new Date().toISOString(), tools }), { mode: 0o600 });
      await rename(temp, cache);
      return tools;
    } catch (error) { await backend.invalidate(client); throw error; }
  })().finally(() => { refreshing = null; });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: tools.length ? tools : await refresh() }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    try { return await backend.call(request.params); }
    catch (error) { return { isError: true, content: [{ type: 'text', text: error.message }] }; }
  });
  await server.connect(new StdioServerTransport());
  const heartbeat = setInterval(async () => {
    const client = backend.client;
    try {
      if (client) await client.ping({}, { timeout: 5000 });
      else await refresh();
    } catch (error) {
      if (client) await backend.invalidate(client);
      process.stderr.write(`cbh-burp: ${error.message}\n`);
    }
  }, 30000);
  heartbeat.unref();
  const shutdown = async () => { clearInterval(heartbeat); await backend.close(); await server.close(); };
  process.stdin.on('end', shutdown);
  process.once('SIGTERM', () => shutdown().finally(() => process.exit(0)));
  process.once('SIGINT', () => shutdown().finally(() => process.exit(0)));
  refresh().catch(error => process.stderr.write(`cbh-burp: ${error.message}\n`));
}
if (process.argv[1] === new URL(import.meta.url).pathname) main().catch(error => { console.error(error.message); process.exit(1); });
