// Operator-driven login into an engagement's persistent Playwright profile.
//
// Why this exists: the MCP Playwright wrapper resolves its profile ONCE at server
// start, and when Claude Code was started outside Targets/<name>/ it runs
// `--isolated`, so a login taken there is thrown away. And the agent cannot type a
// password it is not allowed to read. So: a HEADED chromium on the engagement's own
// profile dir, the operator types the credentials in the window, this script waits
// for the session cookie, writes browser-state.json, and keeps the browser alive on
// a CDP port so the agent can drive it without ever seeing the password.
//
//   node scripts/operator-login.mjs <profile-dir> <state-json> <start-url> [cdp-port] [wait-minutes]
//
// NOTE: a CDP-driven browser bypasses scripts/mcp-gate.py — no scope check, no
// pacing, no audit rows. Keep the navigation minimal and log what was opened by hand.
// ESM ignores NODE_PATH, so the dependency is resolved from the runtime/ install by path.
import { createRequire } from 'node:module';
const require_ = createRequire('/home/qvex/security-research/BugHunter/runtime/');
const playwright = require_('playwright-core');
import { mkdirSync, existsSync } from 'node:fs';
import { acquireProfileLock, busyMessage } from '../runtime/browser-lock.mjs';

const [profileDir, statePath, startUrl, portArg, waitArg] = process.argv.slice(2);
if (!profileDir || !statePath || !startUrl) {
  console.error('usage: operator-login.mjs <profile-dir> <state-json> <start-url> [cdp-port] [wait-minutes]');
  process.exit(2);
}
// Which engine, same knob and same default as runtime/playwright-mcp.mjs. It matters
// here twice: a Chromium user-data-dir is not a Firefox profile (so the caller must
// hand us the engine's OWN profile dir — engine/browser_doctor.py resolves it through
// browser_state.profile_dir_name), and only Chromium takes --remote-debugging-port, so
// for firefox/webkit this script saves the state and EXITS instead of holding the
// profile open on a CDP port the agent could not attach to anyway.
const engine = (process.env.CBH_PLAYWRIGHT_BROWSER || 'chromium').toLowerCase();
if (!['chromium', 'firefox', 'webkit'].includes(engine)) {
  console.error(`operator-login: CBH_PLAYWRIGHT_BROWSER=${engine} is not chromium|firefox|webkit.`);
  process.exit(2);
}
const browserType = playwright[engine];
const port = Number(portArg || 9222);
const waitMs = Number(waitArg || 15) * 60_000;
const COOKIE = process.env.LOGIN_COOKIE || 'refresh_token';

mkdirSync(profileDir, { recursive: true, mode: 0o700 });

// Chromium allows ONE browser per --user-data-dir, and runtime/playwright-mcp.mjs takes
// this same lock for the hunting lane. Without it this window would sit inside Chromium's
// SingletonLock with no error for the length of that lane — the operator would be staring
// at a window that never paints and conclude the login flow is broken.
const lock = await acquireProfileLock(profileDir, { label: 'operator-login' });
if (!lock.ok) {
  console.error(busyMessage(lock, profileDir));
  process.exit(1);
}
process.once('exit', lock.release);
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => { lock.release(); process.exit(130); });
}

// The same binary the hunting lane uses (runtime/playwright-mcp.mjs resolves this list
// too). It matters twice: bundled Chromium is RST'd by some targets as
// net::ERR_TOO_MANY_RETRIES, and the profile written here is REUSED by the MCP lane —
// one profile dir written by two different browser builds is how a saved login stops
// being read back.
// Chromium only: an --executable-path from this list would be the wrong binary for
// another engine, and Playwright resolves its own firefox/webkit builds.
const chromeBin = engine !== 'chromium' ? null : [
  process.env.CBH_PLAYWRIGHT_CHROME,
  '/opt/google/chrome/chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/google-chrome',
].find(p => p && existsSync(p));

const ctx = await browserType.launchPersistentContext(profileDir, {
  headless: false,
  viewport: null,
  ...(chromeBin ? { executablePath: chromeBin } : {}),
  ...(engine === 'chromium' ? { args: [`--remote-debugging-port=${port}`] } : {}),
});
console.log(`ENGINE        ${engine}`);
console.log(`BROWSER       ${chromeBin || `playwright bundled ${engine}`}`);
const page = ctx.pages()[0] || await ctx.newPage();
await page.goto(startUrl, { waitUntil: 'domcontentloaded' }).catch(e => console.error('goto:', e.message));

console.log(`WINDOW OPEN   ${startUrl}`);
if (engine === 'chromium') console.log(`CDP           http://127.0.0.1:${port}`);
console.log(`PROFILE       ${profileDir}`);
console.log(`WAITING for a '${COOKIE}' cookie — type the credentials in the window.`);

const deadline = Date.now() + waitMs;
let logged = false;
while (Date.now() < deadline) {
  const cookies = await ctx.cookies().catch(() => []);
  if (cookies.some(c => c.name === COOKIE)) { logged = true; break; }
  await new Promise(r => setTimeout(r, 3000));
}

if (!logged) {
  console.log('TIMEOUT — no session cookie appeared. Browser left open; re-run or finish by hand.');
} else {
  await ctx.storageState({ path: statePath });
  const names = (await ctx.cookies()).map(c => c.name).sort();
  console.log(`LOGGED IN     url=${page.url()}`);
  console.log(`STATE SAVED   ${statePath}`);
  console.log(`COOKIES       ${names.join(', ')}`);
}
if (engine === 'chromium') {
  console.log('BROWSER STAYS OPEN — drive it over CDP. Close this process to end the session.');
  await new Promise(() => {});
} else {
  // Firefox/WebKit take no CDP port, and one browser holds the profile directory
  // exclusively: staying open would block the MCP hunting lane from ever reading the
  // login back. The cookies are already on disk in the persistent profile, so the
  // right move is to hand the profile back.
  await ctx.close().catch(() => {});
  console.log(`BROWSER CLOSED — the login is in the persistent profile ${profileDir};`);
  console.log('the MCP Playwright lane reads it back on its next navigation.');
  process.exit(logged ? 0 : 1);
}
