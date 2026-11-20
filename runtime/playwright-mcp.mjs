// Playwright MCP wrapper — headless Chromium, scoped and paced by scripts/mcp-gate.py.
//
// Session persistence is the point of the engagement branch below. Playwright's
// `--storage-state` only LOADS a state file (it never writes one back), and
// `--isolated` keeps the profile in memory, so every run used to start logged out.
// The hunters who measured this had 80% of their tokens going to logins, and the
// money is behind the login. So inside an engagement the browser gets a persistent
// per-engagement profile, which Chromium itself keeps up to date; outside one it
// stays in-memory, because lab work should not leave a profile behind.
//
// The profile holds live session cookies — credential material, same class as
// identity.json. It lives inside Targets/<name>/ and is git-ignored there.
import { spawnSync } from 'node:child_process';
import { spawnGated, inlineGateActive } from './inline-gate.mjs';
import { acquireProfileLock, busyMessage } from './browser-lock.mjs';
import net from 'node:net';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { overlayRepoMcpEnv, repoDir, runtimeDir } from './client.mjs';

overlayRepoMcpEnv('playwright');

const output = path.join(runtimeDir, 'artifacts', `browser-${process.pid}`);
mkdirSync(output, { recursive: true, mode: 0o700 });

// engine/identity.py owns the question "which engagement is this, and does it want
// session reuse" — profile.json can switch it off with "browser_session_reuse": false.
function engagementState() {
  if (process.env.CBH_PLAYWRIGHT_ISOLATED === '1') return null;
  try {
    const r = spawnSync('python3', [path.join(repoDir, 'engine', 'identity.py'), 'storage-state'],
      { encoding: 'utf8', timeout: 10000, cwd: process.cwd() });
    const line = (r.stdout || '').trim();
    return r.status === 0 && line ? line : null;
  } catch { return null; }
}

// Headed window: Grok / any inline-gated client with a display. Claude Code
// (CLAUDECODE=1, no GROK_*) stays headless. Grok Build's compat layer leaks
// CLAUDECODE=1 into MCP, so GROK_AGENT / GROK_SESSION_ID still win.
//
// Caido proxy is independent of that: the browser ALWAYS goes through
// 127.0.0.1:8080 unless CBH_PLAYWRIGHT_CAIDO=off or CBH_PLAYWRIGHT_PROXY is set.
// Silent fallback to direct was the bug (operator 2026-11-11). Overrides:
// CBH_PLAYWRIGHT_HEADLESS=1, CBH_PLAYWRIGHT_HEADED=1, CBH_PLAYWRIGHT_CAIDO=off,
// CBH_PLAYWRIGHT_PROXY=<url>.
const watched = inlineGateActive()
  || process.env.GROK_AGENT === '1'
  || Boolean(process.env.GROK_SESSION_ID)
  || process.env.CBH_PLAYWRIGHT_HEADED === '1';
const hasDisplay = Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
const headless = process.env.CBH_PLAYWRIGHT_HEADLESS === '1'
  || !hasDisplay
  || (!watched && process.env.CBH_PLAYWRIGHT_HEADED !== '1');

function portOpen(host, port, ms = 700) {
  return new Promise(resolve => {
    const sock = net.connect({ host, port });
    const done = ok => { sock.destroy(); resolve(ok); };
    sock.setTimeout(ms, () => done(false));
    sock.once('connect', () => done(true));
    sock.once('error', () => done(false));
  });
}

const caidoHost = process.env.CBH_CAIDO_HOST || '127.0.0.1';
const caidoPort = Number(process.env.CBH_CAIDO_PORT || 8080);
// Resolve the engagement first: a `playwright-direct` marker next to
// browser-state.json skips Caido. mail.ru RST/hangs Chrome through MITM
// (net::ERR_TOO_MANY_RETRIES) even with --disable-http2; curl/bbcurl still
// work direct. Default remains Caido-on (silent proxy-less fallback was the bug).
const statePath = process.env.CBH_PLAYWRIGHT_STORAGE_STATE || engagementState();
function engagementWantsDirect(p) {
  if (!p) return false;
  try {
    const dir = path.dirname(p);
    return existsSync(path.join(dir, 'playwright-direct'))
      || existsSync(path.join(dir, 'browser-profile', 'direct'));
  } catch { return false; }
}
const wantCaido = !process.env.CBH_PLAYWRIGHT_PROXY
  && (process.env.CBH_PLAYWRIGHT_CAIDO || 'on') !== 'off'
  && !engagementWantsDirect(statePath);

if (wantCaido && !(await portOpen(caidoHost, caidoPort))) {
  spawnSync('bash', [path.join(repoDir, 'scripts', 'caido-up.sh'), '--quiet'], {
    encoding: 'utf8', timeout: 35000, stdio: 'inherit',
  });
}
const caidoUp = wantCaido && await portOpen(caidoHost, caidoPort);
if (wantCaido && !caidoUp) {
  console.error(`Playwright MCP: Caido is down at ${caidoHost}:${caidoPort} after caido-up. Not starting a proxy-less browser. Set CBH_PLAYWRIGHT_CAIDO=off to override.`);
  process.exit(1);
}
const viaCaido = Boolean(caidoUp);

// Which engine. Default chromium. CBH_PLAYWRIGHT_BROWSER=firefox|webkit switches it.
// Why this is a knob and not a constant: measured 2026-11-12, o2.mail.ru sends
// `critical-ch: ... Sec-CH-UA-Full-Version-List` and fails CLOSED on a version it
// does not know (Chrome 155 -> mail.ru/badbrowser, no continue-anyway control),
// which walls every authenticated browser lane on the estate. A plain curl client,
// which volunteers no client hints at all, is served the real login page. Firefox
// does not implement UA client hints either, so it is served the page for the same
// reason curl is. That is a browser choice, not a spoofed header: nothing lies
// about what it is.
const engine = (process.env.CBH_PLAYWRIGHT_BROWSER || 'chromium').toLowerCase();
if (!['chromium', 'firefox', 'webkit'].includes(engine)) {
  console.error(`Playwright MCP: CBH_PLAYWRIGHT_BROWSER=${engine} is not chromium|firefox|webkit.`);
  process.exit(1);
}

const args = [path.join(runtimeDir, 'node_modules/@playwright/mcp/cli.js'),
  ...(headless ? ['--headless'] : []), '--browser', engine, '--output-dir', output];

// Playwright's bundled Chromium is RST'd by mail.ru (and similar) as
// net::ERR_TOO_MANY_RETRIES. Installed Google Chrome loads the same URL.
// Override: CBH_PLAYWRIGHT_CHROME=/path/to/chrome
// Chromium only: an --executable-path from this list would be the wrong binary for
// another engine, and Playwright resolves its own firefox/webkit builds.
const chromeBin = engine !== 'chromium' ? null : [
  process.env.CBH_PLAYWRIGHT_CHROME,
  '/opt/google/chrome/chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/google-chrome',
].find(p => p && existsSync(p));
if (chromeBin) args.push('--executable-path', chromeBin);

// A Chromium user-data-dir is not a Firefox profile, so each engine gets its own
// directory. Switching engines therefore means logging in again in that profile.
const profileName = engine === 'chromium' ? 'browser-profile' : `browser-profile-${engine}`;
const profileDir = statePath ? path.join(path.dirname(statePath), profileName) : null;

// A profile held by another session used to be fatal here, and a dead MCP server does not
// respawn: measured 2026-11-20, .mcp.json named standoff365/wildberries (written by another
// session), that profile was held by a second Claude session, this server waited the full
// 25 s for the lock, missed Claude Code's 30 s connect timeout and left the session with no
// browser at all. At server start the wait is now short and a busy profile falls back to an
// in-memory one (logged out, no lock), so the session keeps a browser. Set
// CBH_PLAYWRIGHT_REQUIRE_PROFILE=1 to keep the old fail-closed behaviour.
let lock = null;
// `fresh` before the lock: acquireProfileLock creates the directory.
const fresh = Boolean(profileDir) && !existsSync(profileDir);
if (profileDir) {
  const startWaitMs = process.env.CBH_BROWSER_LOCK_WAIT_SECONDS ? undefined : 3000;
  lock = await acquireProfileLock(profileDir, startWaitMs === undefined ? {} : { waitMs: startWaitMs });
  if (!lock.ok) {
    console.error(busyMessage(lock, profileDir));
    if (process.env.CBH_PLAYWRIGHT_REQUIRE_PROFILE === '1') process.exit(1);
    console.error('Playwright MCP: falling back to an in-memory (--isolated) profile so this '
      + 'session still has a browser; it starts logged out.');
  }
}
if (profileDir && lock && lock.ok) {
  // One browser per --user-data-dir. Without this, a second server sits inside Chromium's
  // SingletonLock with no error for the length of the first lane — 19 of 38 subagents were
  // killed that way on 2026-11-11. See runtime/browser-lock.mjs.
  process.once('exit', lock.release);
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, lock.release);
  mkdirSync(profileDir, { recursive: true, mode: 0o700 });
  args.push('--user-data-dir', profileDir);
  // A state file only gets imported into a profile that does not exist yet. After
  // that the profile is the live session and the state file would be the stale one.
  if (fresh && existsSync(statePath)) args.push('--storage-state', statePath);
} else {
  args.push('--isolated');
  if (statePath && existsSync(statePath)) args.push('--storage-state', statePath);
}
if (process.env.CBH_PLAYWRIGHT_PROXY) args.push('--proxy-server', process.env.CBH_PLAYWRIGHT_PROXY);
else if (viaCaido) {
  args.push('--proxy-server', `http://${caidoHost}:${caidoPort}`, '--ignore-https-errors');
  // HTTP/2 and QUIC stay off so the wire Caido records is the HTTP/1.1 it replays. The old
  // note here blamed HTTP/2 for net::ERR_TOO_MANY_RETRIES; the net-log of 2026-11-18 showed
  // the real cause was the untrusted Caido CA (see `--ignore-certificate-errors` below).
  // Firefox needs the same HTTP/2 off, as launch args --disable-http2 are Chromium-only.
  const cfg = path.join(output, 'caido-launch.json');
  const launchOptions = {};
  if (engine === 'chromium') {
    // `--ignore-certificate-errors` is the fix that was missing. Measured 2026-11-18 with
    // a Chrome net-log through Caido: every attempt failed SSL_CONNECT with
    // ERR_CERT_AUTHORITY_INVALID (Caido's CA is not trusted), and Chrome 155 does NOT let
    // the context-level `ignoreHTTPSErrors` absorb that on a proxied connection — it
    // reconnects ~32 times and surfaces net::ERR_TOO_MANY_RETRIES in ~150 ms. That is the
    // error the `playwright-direct` markers on 1password and mail_vk were written for, and
    // it failed on example.com too. With this switch example.com and chromewebstore load
    // 200 through Caido over HTTP/1.1 and HTTP/2 alike. Firefox was never affected
    // (`security.enterprise_roots.enabled` below). The browser only ever talks to Caido.
    launchOptions.args = ['--disable-http2', '--disable-quic', '--ignore-certificate-errors'];
  } else if (engine === 'firefox') {
    launchOptions.firefoxUserPrefs = {
      'network.http.http2.enabled': false,
      'network.http.http3.enabled': false,
      'network.proxy.allow_hijacking_localhost': true,
      'security.enterprise_roots.enabled': true,
    };
  }
  writeFileSync(cfg, JSON.stringify({
    browser: {
      launchOptions,
      contextOptions: { ignoreHTTPSErrors: true },
    },
  }));
  args.push('--config', cfg);
  console.error(`Playwright MCP: proxy http://${caidoHost}:${caidoPort} (Caido)`);
  // Caido files every proxied request under its ONE current project, and every programme
  // shares one: `bughunter` (operator directive 2026-11-18). Nothing used to choose it, so
  // whatever was current got the traffic. Re-select it before the first proxied byte; an
  // error is reported, never fatal.
  try {
    const r = spawnSync('python3', [path.join(repoDir, 'engine', 'caido_project.py'),
      '--ensure'],
      { encoding: 'utf8', timeout: 15000, cwd: process.cwd() });
    const line = `${r.stdout || ''}${r.stderr || ''}`.trim();
    if (line) console.error(`Playwright MCP: ${line}`);
  } catch (e) {
    console.error(`Playwright MCP: caido-project not bound (${e.message})`);
  }
}
args.push(...process.argv.slice(2));

const child = spawnGated('playwright', process.execPath, args, { env: process.env });
child.on('error', error => { console.error(`Playwright MCP: ${error.message}; run npm ci in ${runtimeDir}`); process.exit(1); });
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => child.kill(signal));
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
