import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { runtimeDir } from './client.mjs';

const output = path.join(runtimeDir, 'artifacts', `browser-${process.pid}`);
mkdirSync(output, { recursive: true, mode: 0o700 });
const args = [path.join(runtimeDir, 'node_modules/@playwright/mcp/cli.js'),
  '--headless', '--isolated', '--browser', 'chromium', '--output-dir', output];
if (process.env.CBH_PLAYWRIGHT_STORAGE_STATE) args.push('--storage-state', process.env.CBH_PLAYWRIGHT_STORAGE_STATE);
if (process.env.CBH_PLAYWRIGHT_PROXY) args.push('--proxy-server', process.env.CBH_PLAYWRIGHT_PROXY);
args.push(...process.argv.slice(2));
const child = spawn(process.execPath, args, { stdio: 'inherit', env: process.env });
child.on('error', error => { console.error(`Playwright MCP: ${error.message}; run npm ci in ${runtimeDir}`); process.exit(1); });
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => child.kill(signal));
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
