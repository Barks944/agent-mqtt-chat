<!-- req:help:agents:begin -->

<!-- Managed by `req help agents --install`. Re-run to refresh; edit OUTSIDE the markers to add your own notes. -->

## req — agents

_What req does for you as an agent, and how to use it._

```
Hey. If you're an LLM agent picking up this project — this is for you.

WHY THIS EXISTS (the short version)

  Vibecoding sessions are conversational. The user describes what they
  want, you build it, the conversation ends. Without something carrying
  the spec between sessions, the next conversation starts blind: you
  re-discover the project from source files, you re-derive the intent,
  and small things drift.

  `req` is the spec-memory that survives between conversations. The
  project's requirements live in a git-tracked JSON file managed by
  this CLI. The tool tells you what's there, what's queued, and what's
  loose. Hooks remind you at commit time. It's there so you can pick
  up where the last session left off, instead of guessing.

START HERE

  req brief                    one-line summary of where the project is
                               right now. Run this first in any session.
                               Now leads with the project's `_purpose`
                               (REQ-NNNN) plus its top three Must/Verified
                               requirements — the spine — so you learn
                               what the project is FOR before what's queued.
  req list                     full list of requirements with status
  req show REQ-NNNN            details + history for one requirement
  req next                     suggests what to work on, dependency-aware

WHEN THE USER ASKS FOR SOMETHING NEW

  req add --title "..." \        record the requirement BEFORE you write
          --statement "..." \    the code. The statement should have a
          --rationale "..." \    modal verb (shall / must / should / will)
          --kind functional \    and describe one obligation. The conformance
          --priority must \      checker tells you if it doesn't.
          --accept "..."

  Then drop a `// REQ-NNNN:` comment in the file that implements it.
  When you commit, the pre-commit hook checks that source files cite
  the REQs they implement. The post-commit hook prints a one-line
  summary so you see what landed.

WHILE YOU WORK

  req coverage --path src      where are the markers? what's orphaned?
  req conform                 are the requirements well-formed?
  req lint                     softer audit (rationale length, etc.)
  req precheck                 run the local CI gate suite (REQ-NNNN) —
                               fmt + clippy + test + conform + coverage
                               + review, in CI's order. Catches the
                               environment-skew failures (rustfmt drift,
                               fixture-config flakiness) that otherwise
                               only show up after push.

WORKING WITH AN EXISTING PROJECT (RETROFIT)

  req adopt REQ-NNNN REQ-NNNN  walk a list of requirements through the
                               lifecycle to Verified in one invocation
                               (REQ-NNNN). One history entry per hop,
                               auto-placeholder acceptance for functional
                               reqs that lack one, inspection evidence
                               recorded when the target is Verified.
  req adopt --all-drafts       same, scoped to every requirement at Draft.
  req adopt --to implemented   stop short of Verified.
  req adopt --dry-run          show the plan without writing.

  The retrofit path matters because the lifecycle state machine exists
  to make ongoing work disciplined — not to make loading existing state
  painful. `req adopt` is the explicit acknowledgement that those are
  two different modes.

WHEN YOU FINISH SOMETHING

  req update <id> --status implemented --reason "..."

  Then VERIFY it before claiming Verified. Don't one-shot it — walk
  the verification dossier so the pass/fail is backed by real analysis
  and testing (REQ-NNNN):

    req verification plan     <id> --plan "how I'll review + test this"
    req verification analysis <id> --findings "code-review notes" --result pass
    req verification test     <id> --findings "what I ran" --result pass
    req verification conclude <id> --statement "why this passes" --promote

  `conclude` derives the verdict (Pass only when BOTH analysis and
  testing passed) and `--promote` flips status to Verified. Promotion
  is BLOCKED without a passing dossier — this holds for `req verify`
  and `req sreq verify --promote` too. A trivial ordinary requirement
  can carry a `verification-exempt` tag (or use `req verify --no-dossier
  --reason "..."`); safety requirements have no exemption. Works on
  both REQ-NNNN and SR-NNNN ids.

  The post-commit hook nudges you about advancing status — if you
  cited a REQ but didn't advance it, the hook prints a suggestion.

  CODE CHANGED LATER? The dossier anchors a hash of the linked source,
  so `req stale` flags a Verified item whose code moved since you
  verified it. Re-verify with `req verification plan <id> --reopen
  --reason "..."`.

HOW THE FILE IS PROTECTED

  `project.req` is just JSON — there's nothing at the filesystem
  level stopping you from opening it in an editor. The contract is
  *post-hoc*: every change passes through an integrity hash, and
  any edit that didn't go via the CLI will fail your next `req`
  call until `req repair --confirm-direct-edit` re-signs it.
  Agents that bypass the CLI don't break anything silently — they
  just trigger a visible repair audit on the next operation.

  This isn't about gatekeeping you. It's so the diff in any PR
  reflects something the CLI was willing to record — the
  guarantee humans rely on when reviewing.

RULES THAT MATTER (the short list)

  * One obligation per requirement (the conformance checker catches compounds).
  * A normative modal verb in every statement.
  * Pass `--reason` on every update so history attributes the why.
  * `// REQ-NNNN:` markers in source link spec to code.
  * Status only goes forward one step at a time; backwards needs
    `--force --reason`. Same for skips.

NEW SESSION? RUN THIS FIRST.

  req brief

  That tells you where the project is. From there, `req next` to
  pick something up or just start fixing what the user described.

INSTALL THIS GUIDANCE

  req help agents --install      writes a managed block into AGENTS.md
                                 (between sentinel markers — idempotent,
                                 re-run any time to refresh).

MCP (Model Context Protocol)

  An MCP server is built in. Run `req mcp` and connect from an
  MCP-capable client (Claude Code, etc.). Or `req mcp --init-config`
  to write `.mcp.json` for auto-launch. The full surface (25 tools)
  is documented at `req help mcp`.

ONE-LINE BOOTSTRAP FOR A NEW PROJECT

  req setup     # init + hooks + AGENTS.md, all in one.
```

<!-- req:help:agents:end -->
