# PTAS Terminal Sidecar

## Complete student workflow

From the repository root, start the terminal-first workflow with:

```bash
./ptas.sh start
```

When tmux is available, PTAS creates two panes:

- The left pane asks the student to register or log in, select or create a
  project, enter the authorized scope, and enter the training target.
- The right pane displays authentication state, scope confirmation, scan
  progress, completed findings, hard-coded validation suggestions, and the
  final report command.

The student must answer `yes` to the authorization confirmation before a scan
can start. PTAS then runs a quick discovery stage followed by a detailed service
assessment. Suggestions do not appear until the final scan stage completes.
Suggested commands are non-destructive validation steps and are never run
automatically.

Each scan stage prints its completed findings in the left pane and publishes
them to the right monitor pane. Nmap findings become available when that stage
finishes; they are not inferred from partial output while Nmap is still running.
Final validation suggestions are saved as recommendation records, so they also
appear inside the generated JSON report.

After the normal scan stages, PTAS asks whether to include CVE checks. Answering
`yes` runs only Nmap scripts tagged both `vuln` and `safe`. This includes the
external Vulners correlation service, which receives detected product/version
or CPE data. Results are classified as:

- `CONFIRMED_CVE` only when an applicable NSE script explicitly returns a
  `VULNERABLE` state and a CVE identifier.
- `CVE_CANDIDATE` when Vulners correlates a detected product/version with CVE
  records. Candidates require manual product, patch, and vendor-advisory
  verification and are not proof of exploitability.
- `EXPLOIT_DB_REFERENCE` when Kali's local `searchsploit` database contains one
  or more version-specific Exploit-DB entries with CVE identifiers. The report
  includes each `EDB-ID`, title, CVEs, and whether Exploit-DB marks the entry as
  verified. “Verified” describes the Exploit-DB entry, not the scanned host.

PTAS does not run the unrestricted Nmap `vuln` category.

Exploit-DB matching is deliberately skipped when Nmap cannot identify a
concrete product/version. Searching a generic service name such as `mysql`
would return unrelated results and create false CVEs. Exploit-DB enrichment is
local and read-only; keep Kali's `exploitdb` package/database updated through
the normal trusted package-management process.

## Service-aware scanning tools

Nmap remains the discovery source, but it is no longer the only assessment
tool. After discovery, PTAS selects applicable installed tools from the
observed service type:

| Service | Automatic bounded tools |
| --- | --- |
| HTTP/HTTPS | WhatWeb, curl headers, Nikto, and Gobuster with Kali's small common-path wordlist |
| HTTPS/TLS | SSLScan in addition to the HTTP checks |
| SMB/NetBIOS | enum4linux-ng |
| DNS hostname resolution | dig |
| MySQL/MariaDB | mysqladmin availability and authentication-boundary check |
| PostgreSQL | pg_isready availability check |
| Redis | redis-cli PING authentication-boundary check |
| Version/CVE research | safe NSE checks, Vulners with consent, and local Searchsploit |

Every tool is launched as an argument list without a shell, has a timeout, and
has its sanitized output size limited before persistence. Missing tools are
skipped. Results are stored as `TOOL_OBSERVATION` or `TOOL_CVE_CANDIDATE`
findings and appear in the report.

PTAS intentionally does not automatically run Nuclei, unrestricted FFUF,
arbitrary wordlists, password attacks, exploitation frameworks, or every Kali
tool. Those behaviors cannot be safely inferred from an open port and may be
intrusive. Run `./ptas.sh doctor` to see which bounded integrations are
available locally.

The scope and target are separate prompts. For one VM, both may be the same:

```text
Authorized scope: 192.168.56.101
Training target inside that scope: 192.168.56.101
```

For a lab subnet, enter the subnet first and then one host inside it:

```text
Authorized scope: 192.168.56.0/24
Training target inside that scope: 192.168.56.101
```

Invalid input is requested again without cancelling the complete session.

To run without tmux:

```bash
./ptas.sh start --no-tmux
```

At the end, PTAS prints a scan-specific command similar to:

```bash
./ptas.sh report --scan-id 12 --output reports/ptas-scan-12.json
```

Run that command from the repository root to generate the database report and
save its JSON content at the displayed location.

### One recommendation at a time

After an assessment, request the first stored validation recommendation with:

```bash
./ptas.sh recommend --scan-id 12
```

PTAS shows the associated finding, CVE references when present, purpose, and
one reviewable command. It never executes the command. Run the same command
again to receive the next recommendation:

```bash
./ptas.sh recommend --scan-id 12
```

In the two-pane workflow, after the student executes the displayed validation
command and the left shell prompt returns, the monitor automatically advances
and displays the next stored recommendation. Manual `recommend` commands remain
available when a command is skipped or when using single-terminal mode.

Progress is stored locally in `.ptas/recommendation-state.json`. Restart the
sequence with:

```bash
./ptas.sh recommend --scan-id 12 --reset
```

Every recommendation response, automatically emitted suggestion, and
post-command left-pane observation also prints the exact report-generation
command for the current scan.

The `report` command now saves both structured JSON and a formatted standalone
HTML report. For example, this command creates `ptas-scan-12.json` and
`ptas-scan-12.html`:

```bash
./ptas.sh report --scan-id 12 --output reports/ptas-scan-12.json
```

Convert an existing JSON report without starting MariaDB:

```bash
./ptas.sh render-report reports/ptas-scan-12.json
```

The HTML file contains summary cards, severity breakdowns, finding evidence,
CVE links, recommendations, commands, and print styling. Open it in a browser
and use the browser's Print dialog to save a PDF when needed.

After the guided scan completes, the left pane intentionally returns to a
normal shell so the student can run the displayed validation and report
commands. The tmux session remains open. Press `Ctrl-b`, then `d`, to detach;
later use `tmux attach` to return.

## Standalone sidecar

The PTAS sidecar watches one explicitly selected terminal source and displays
read-only suggestions in another terminal. It never executes a suggested
command.

## Recommended Kali workflow: tmux

Install the project and make the launchers executable:

```bash
./kali-setup.sh
chmod +x start.sh ptas.sh
```

Start a tmux session:

```bash
tmux new-session -s ptas
```

Split it into two panes with `Ctrl-b %`. Use the left pane for your normal
authorized assessment and the right pane for PTAS. List the pane IDs:

```bash
tmux list-panes -F '#{pane_id}  #{pane_current_command}'
```

If the working pane is `%0`, run this in the assistant pane:

```bash
./ptas.sh watch --pane %0 --scope 10.10.10.0/24
```

Repeat `--scope` for every authorized network or domain:

```bash
./ptas.sh watch \
  --pane %0 \
  --scope 10.10.10.0/24 \
  --scope lab.example.test
```

You can also maintain scope in a text file:

```text
# scope.txt
10.10.10.0/24
lab.example.test
```

```bash
./ptas.sh watch --pane %0 --scope-file scope.txt
```

The watcher establishes the existing pane content as its baseline, then
analyzes only new content. Press `Ctrl+C` in the assistant pane to stop it.

## Optional local Ollama advice

Rules-based advice is the default and requires no model. To add a locally
installed Ollama model:

```bash
ollama serve
./ptas.sh watch \
  --pane %0 \
  --scope 10.10.10.0/24 \
  --provider ollama \
  --model YOUR_INSTALLED_MODEL
```

PTAS refuses to send terminal excerpts to a non-local Ollama URL unless
`--allow-remote-llm` is explicitly supplied. Review the privacy impact before
enabling that option.

## Transcript mode

When tmux is unavailable, a terminal can write a transcript:

```bash
script -q -f /tmp/ptas-session.log
```

Then watch it from another terminal:

```bash
./ptas.sh watch \
  --file /tmp/ptas-session.log \
  --scope 10.10.10.0/24
```

The raw file produced by `script` is not sanitized and may contain sensitive
data. Store it securely and remove it when it is no longer needed. PTAS
sanitizes content before analysis and before writing its optional audit log.

## Analyze saved output once

```bash
./ptas.sh analyze nmap-output.txt --scope 10.10.10.0/24
```

Or pipe output directly:

```bash
nmap -sV 10.10.10.20 | ./ptas.sh analyze - \
  --target 10.10.10.20 \
  --scope 10.10.10.0/24
```

## Optional audit log

```bash
./ptas.sh watch \
  --pane %0 \
  --scope 10.10.10.0/24 \
  --audit-log .ptas/session.jsonl
```

Audit logging is off by default. Logs contain sanitized commands, structured
findings, and suggestions; they do not contain the full raw transcript.

## Diagnostics

```bash
./ptas.sh doctor
python3 -m unittest discover -v
```

The initial parser recognizes Nmap port output, HTTP status lines, common web
enumeration paths, and common runtime errors. Unknown output remains visible in
the working pane but does not produce speculative findings.

## Safety boundaries

- Only a pane or file named by the operator is observed.
- At least one authorized scope entry is mandatory.
- Out-of-scope targets produce a stop warning and no testing advice.
- Common tokens, passwords, cookies, credentials in URLs, and private keys are
  redacted before analysis.
- Suggestions are advisory and are never automatically executed.
- An open port is treated as an observation, not proof of a vulnerability.
