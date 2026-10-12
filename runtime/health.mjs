import path from 'node:path';
import { burpUrl, connect, listAllTools, runtimeDir } from './client.mjs';

const start = process.argv.includes('--start');
const only = process.argv.find(arg => arg.startsWith('--only='))?.split('=')[1];
const entries = {
  burpmcp: start ? { command: process.execPath, args: [path.join(runtimeDir, 'burp-bridge.mjs')] } : { url: burpUrl },
  playwright: { command: process.execPath, args: [path.join(runtimeDir, 'playwright-mcp.mjs')] },
};
const checks = await Promise.all(Object.entries(entries).filter(([name]) => !only || name === only).map(async ([name, entry]) => {
  let client;
  const began = Date.now();
  try {
    client = await connect(entry, start ? 180000 : 15000);
    const tools = await listAllTools(client, start ? 180000 : 15000);
    if (!tools.length) throw new Error('tools/list is empty');
    return { name, status: 'ready', tools: tools.map(tool => tool.name), duration_ms: Date.now() - began };
  } catch (error) { return { name, status: 'failed', error: error.message, duration_ms: Date.now() - began }; }
  finally { await client?.close().catch(() => {}); }
}));
console.log(JSON.stringify({ checked_at: new Date().toISOString(), checks }, null, 2));
process.exitCode = checks.length && checks.every(check => check.status === 'ready') ? 0 : 1;
