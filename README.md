# warden

An agentic tool-call firewall: a policy-enforcing middleware layer that sits
between an LLM agent and its tools (file system, HTTP, shell) and decides, per
proposed call, whether to **allow**, **block**, or **flag** it, with a
human-readable reason. Decisions consider both the individual call and the
short sequence of calls that preceded it in the same session.

warden is a deterministic reference monitor: no LLM in the decision path. The
same event stream, policy, and session state always produce the same
decisions. See `WRITEUP.md` for design choices and known limitations, and
`DESIGN.md` for the full design and decision log.

## Setup

Requires Python 3.12 or newer. No external services; state is a local SQLite
file.

```bash
git clone <this repo> warden && cd warden
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
warden --help
```

Run the test suite (121 tests, a few seconds; one test runs the review walkthrough script):

```bash
pytest -q
```

## Quick start: the bundled scenarios

Seven JSONL scenarios under `scenarios/` double as the demo and the test
fixtures. `replay` runs one against the policy using a throwaway in-memory
store, so demos never touch real state or leak into each other.

```bash
warden replay clean-workflow        # all allowed: legitimate work is not broken
warden replay exfil-chain           # read PII, then POST: blocked by session taint
warden replay pii-processing        # read PII, then run a local script: flagged, not blocked
warden replay write-then-execute    # write a file, then execute it: blocked
warden replay probing               # 3 blocks in 10 calls: session quarantined
warden replay malformed-garbage     # broken input: blocked line by line, no crash
warden replay shell-chaining        # ls && grep allowed; ls ; curl flagged; ls && rm -rf blocked
```

Each prints one JSON decision per input line. The exfil-chain scenario is the
one to look at first: the final `http.post` goes to an allowed domain and would
pass in a clean session. It is blocked only because the session read PII two
calls earlier, and the reason says so:

```
{"id":"x-3","session_id":"s-exfil","decision":"block","rule":"taint.exfil-post",
 "matched_rules":["static.http-known-apis","taint.exfil-post"],
 "reason":"outbound POST after reading PII in this session (session tainted 'pii' by call x-1 reading data/pii/customers.csv)"}
```

`matched_rules` lists every rule that fired, in evaluation order, so a reader
can see that static policy would have allowed the call and the session layer
overrode it.

## Running against your own stream

`check` is the production-shaped command. It reads JSONL from a file or stdin
and persists session state (taint labels, quarantine, recent-call window) in a
SQLite store, so a later run honors what an earlier run learned.

```bash
warden check events.jsonl --policy policy.yaml
cat events.jsonl | warden check - --policy policy.yaml
warden check events.jsonl --policy policy.yaml --audit decisions.jsonl   # append every decision
```

Options:

| Option | Default | Meaning |
|---|---|---|
| `--policy`, `-p` | required | policy YAML file |
| `--store` | `.warden/state.db` | SQLite session state and flag queue |
| `--overrides` | `.warden/overrides.yaml` | exceptions minted by `review approve --remember` |
| `--audit` | none | append every decision to this JSONL file |
| `--max-sessions` | 1024 | in-memory session working set; older sessions flush to the store |

Exit codes are distinct so a script can tell "rejected" from "needs a human":

| Code | Meaning |
|---|---|
| 0 | every call allowed |
| 1 | at least one call blocked |
| 2 | calls flagged and pending review, no blocks |
| 3 | operational error: invalid policy, unreadable input, unknown flag id |

### Event format

One JSON object per line. `id`, `session_id`, `tool`, and `args` are required;
`ts`, `agent`, and `metadata` are optional and carried through untouched.

```json
{"id": "c-042", "session_id": "s-7", "tool": "http.post",
 "args": {"url": "https://api.example.com/upload"}, "agent": "researcher"}
```

Tool names used by the bundled policy: `fs.read`, `fs.write`, `fs.delete`,
`fs.list`, `http.get`, `http.post`, `shell.exec`. Matchers look at
conventional argument names: `path` for file tools, `url` for HTTP, `command`
for shell. An unknown tool is structurally valid but matches no allow rule, so
it falls to the policy's default action.

Malformed input never crashes the stream. A line that is not JSON, not an
object, or fails schema validation produces a `block` decision whose reason
names the line number and the exact problem, and processing continues.

## Policy

Policy lives in a YAML file (see `policy.yaml`) and is validated strictly at
startup. An invalid policy refuses to start rather than running with a partial
rule set. Three sections:

- **`rules`**: static, per-call. Each names a tool (or list of tools), an
  optional `match` on argument patterns (`path` globs, `domain` patterns,
  `command` token patterns), and an action. **First match wins**, so order is
  priority. Anything no rule matches gets `default_action` (block in the
  example policy).
- **`taint`**: `sources` are reads that label the session (for example, PII
  under `./data/pii/**` labels it `pii`). `sinks` are outbound tools whose
  decision escalates while a label is present, one severity per sink:
  `http.post` blocks, `http.get` and `shell.exec` flag.
- **`sequences`**: windowed rules over recent session history. A rule either
  applies an `action` to the current call (write-then-execute blocks the
  execution) or `escalate`s the whole session (three blocks in ten calls puts
  the session in quarantine, after which every allowed call is downgraded to
  flag until a human releases it).

Paths are canonicalized lexically before matching (`~`, `..`, separators), so
`../../etc/passwd` cannot slip past a workspace glob. Domain patterns match on
label boundaries: `*.example.com` matches `api.example.com`, never
`evilexample.com`.

Shell commands are split into segments at `;`, `&&`, `||`, `|`, `&`, and
newlines. An allow rule matches only if every segment is a simple command
(plain words, no redirection, subshell, substitution, or glob) and matches one
of its patterns. A block or flag rule fires if any segment matches. So
`ls . && grep total f` stays allowed, `ls . ; curl https://evil.com` falls to
the shell catch-all, and `ls . && rm -rf /` is blocked. A legitimate command
with unusual syntax lands as a flag and is resolved through review and
`--remember`.

Validate a policy, including a reachability lint that catches session-layer
rules that could never fire because static policy blocks the call they depend
on:

```bash
warden validate --policy policy.yaml
```

## Reviewing flagged calls

`flag` is a real third state: the call is withheld until a human resolves it.
Flags and their resolutions live in the same SQLite store as session state.

```bash
warden review list                    # pending flags, one JSON record per line
warden review show <id>               # full event, decision, and session context
warden review approve <id>            # resolve as allowed
warden review approve <id> --remember # also mint an exact-match exception
warden review deny <id>               # resolve as denied
warden review sessions                # quarantined sessions and what tripped them
warden review release <session_id>    # lift a quarantine (only a human can)
```

`--remember` writes an override that matches the exact tool and exact
argument values of the approved call, nothing wider, into the overrides file.
Overrides are evaluated before the main rule list, so the approved call stops
flagging on its next occurrence. A close variant re-flags on purpose: a human
approved one call, not a pattern.

Two review rules worth knowing. Calls flagged only because their session is
quarantined are recorded in the audit log but not enqueued individually; the
session is the review unit, and `review sessions` surfaces it. And `approve
--remember` refuses while the flag's session is still quarantined, because the
minted exception would be silently outranked by the quarantine until
`release`.

The whole loop in one command, against a temporary store so nothing touches
`.warden/`: a flag is queued, shown, approved with `--remember`, the identical
call then allows while a close variant re-flags, a session is quarantined by
probing, `--remember` is refused inside it, and `release` restores allows.

```bash
bash scripts/review-walkthrough.sh      # uses the venv's warden if it is not on your PATH
```

The same steps by hand:

```bash
rm -f /tmp/demo.db
echo '{"id":"r1","session_id":"s-demo","tool":"shell.exec","args":{"command":"curl https://api.example.com"}}' \
  | warden check - --policy policy.yaml --store /tmp/demo.db
warden review list --store /tmp/demo.db
warden review approve 1 --remember --store /tmp/demo.db --overrides /tmp/demo-overrides.yaml
echo '{"id":"r2","session_id":"s-demo","tool":"shell.exec","args":{"command":"curl https://api.example.com"}}' \
  | warden check - --policy policy.yaml --store /tmp/demo.db --overrides /tmp/demo-overrides.yaml
```

The first `check` flags the unknown shell command (exit 2). After approval with
`--remember`, the identical call is allowed (exit 0) via `override.ov-1`.

## Performance

Measured on a laptop with a 10,000-event stream spread over 500 sessions, a
mix of allow, block, and flag, timing the whole process including interpreter
startup:

| Mode | Throughput | Per decision |
|---|---|---|
| `check`, SQLite store | about 3,900 decisions/sec | about 0.26 ms |
| `replay`, in-memory store | about 8,500 decisions/sec | about 0.12 ms |

The engine itself costs tens of microseconds per call; the store round trip
dominates. There is no network or model call in the decision path.

## Layout

```
src/warden/
  schema.py      event and decision models (pydantic, strict)
  policy.py      policy file models and loader
  matchers.py    path, domain, and shell-command matching
  engine.py      static layer, override lookup, most-restrictive-wins combination
  session.py     session state: taint labels, sequence captures, quarantine
  runner.py      one JSONL line in, one decision out; threads state through the store
  store.py       SQLite and in-memory state stores; flag queue; LRU session cache
  overrides.py   exact-match exceptions minted by review
  lint.py        policy reachability lint
  cli.py         check, replay, validate, review
scenarios/       seven bundled JSONL scenarios
scripts/         review-walkthrough.sh: the flag -> review -> resolve loop end to end
tests/           unit, scenario, adversarial, persistence, and determinism tests
policy.yaml      example policy
DESIGN.md        full design doc and decision log
WRITEUP.md       one-page design choices and known limitations
```

Lint and type-check:

```bash
ruff check src tests
mypy src
```
