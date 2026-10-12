# RESTORE — rebuild this setup on a new Windows laptop

Portable data travels in the encrypted `.7z`. Machine-specific parts (Node, caveman, recon tools, Claude auth) get **reinstalled**, not copied — they have hardcoded paths / are OS binaries.

Assume new home = `%USERPROFILE%` (e.g. `C:\Users\<you>`). Run PowerShell unless noted.

---

## 0. Prereqs
- Install **Claude Code**, then log in (`claude` → auth). Do NOT copy old `.claude/.credentials.json`.
- Install **7-Zip** (to extract): `winget install 7zip.7zip`

## 1. Extract the archive
```powershell
& "C:\Program Files\7-Zip\7z.exe" x allur-migration-YYYYMMDD.7z -o"$env:USERPROFILE"
```
Enter the password when prompted. This restores:
- `Targets\allur\` — engagement (scope, notes, hosts, recon, evidence, findings)
- `Claude-BugHunter\` — web-only skill fork (no `.git`; re-`git init` if you want history)
- `CLAUDE.md` — folder context (put at home dir so Claude Code auto-reads it)
- `.claude\projects\...\memory\` — memory files (see step 5 note)

## 2. Node
```powershell
winget install OpenJS.NodeJS.LTS
```
Open a NEW terminal after (PATH refresh). Verify: `node --version` (need ≥18).

## 3. Caveman (token-saving mode) — reinstall, don't copy
```powershell
git clone https://github.com/JuliusBrussee/caveman.git "$env:USERPROFILE\caveman"
node "$env:USERPROFILE\caveman\bin\install.js"
```
Installer registers the plugin + hooks + statusline with correct paths for THIS machine. (Copying the old `settings.json` caveman block would break — it hardcodes the old user path.)

## 4. Recon tools (Windows binaries) — re-download to `~\bin`
```powershell
$bin="$env:USERPROFILE\bin"; $tmp="$env:TEMP\pdtools"; New-Item -ItemType Directory -Force $bin,$tmp | Out-Null
$dl=@{
  httpx="https://github.com/projectdiscovery/httpx/releases/download/v1.10.0/httpx_1.10.0_windows_amd64.zip"
  katana="https://github.com/projectdiscovery/katana/releases/download/v1.6.1/katana_1.6.1_windows_amd64.zip"
  dnsx="https://github.com/projectdiscovery/dnsx/releases/download/v1.2.3/dnsx_1.2.3_windows_amd64.zip"
  ffuf="https://github.com/ffuf/ffuf/releases/download/v2.2.1/ffuf_2.2.1_windows_amd64.zip"
}
foreach($k in $dl.Keys){ $z="$tmp\$k.zip"; curl.exe -sL -o $z $dl[$k]; Expand-Archive $z "$tmp\$k" -Force; Get-ChildItem "$tmp\$k" -Recurse -Filter *.exe | %{ Copy-Item $_.FullName $bin -Force } }
Get-ChildItem $bin -Filter *.exe
```
(Grab newer versions if these 404 — the release URLs age.) Add `~\bin` to PATH or call by full path. Python tools: `python -m pip install ...` as needed (Python ≥3.10).

## 5. Memory (optional)
Claude Code keys memory by working-dir path, so the `projects\<encoded>\memory\` folder name differs on a new machine/username. Easiest: after first `claude` session in the new home, copy the restored `memory\*.md` files into the new `%USERPROFILE%\.claude\projects\<encoded>\memory\` folder (or just keep them handy — `MEMORY.md` is the index). The key one: `caveman-terse-style.md` (terse output preference).

## 6. Verify
- `cd %USERPROFILE%\Targets\allur` then `claude` → it should auto-read `Targets\allur\CLAUDE.md` (engagement rules + scope).
- Restart Claude Code once so caveman hooks load → `[CAVEMAN]` in statusline, terse replies.
- Read `Targets\allur\notes.md` + `hosts\hrqoldau.md` to see where the hunt left off.

---

## Security
- The `.7z` is encrypted (AES-256, filenames hidden). Transfer via USB / direct copy — **not** public cloud.
- `Targets\allur\evidence\` holds target source + possibly sensitive data. Program rules forbid disclosure. Delete the plaintext archive after extracting; keep the `.7z` password out of shared notes.
