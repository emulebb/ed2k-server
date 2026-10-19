# Rules

- Read `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`
  first; it is authoritative for workspace-wide rules.
- Start from
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\reference\AGENT-CHECKLIST.md`
  for the repeatable operating path.

Everything below is this repo's local deltas only:

- This is the managed eMuleBB reference and upstream-contribution fork of
  `https://github.com/andrey23127/ed2k-server`.
- Keep the server Linux-first. On the canonical Windows workspace, build it
  through `python -m emule_workspace build ed2k-server`; do not add native
  Windows build paths.
- Never let Cargo create `target\` in this repository. Generated output belongs
  under `EMULEBB_WORKSPACE_OUTPUT_ROOT`.
- The fork is the sole approved local server for deterministic harness and
  parity runs. The retired Go server is archived and must not be reintroduced.
- Follow upstream closely. Limit local server changes to generic, upstreamable
  testing and observability improvements; keep provider-specific configuration,
  compatibility translation, fixtures, and orchestration in the harness.
- The fork is not an eMuleBB product or production service. Do not wire it into
  release or production campaigns without an explicit follow-up decision.
- Upstream updates are reviewed merges from the `upstream` remote. Do not add
  scheduled or automatic branch synchronization.
