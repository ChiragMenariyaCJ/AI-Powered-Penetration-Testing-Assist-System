# PTAS Terminal Sidecar

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
