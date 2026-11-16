# Harness configuration captures

`harness-cli.json` records real `mcp get` responses from Claude Code 2.1.325,
Claude Code 2.1.0, and Codex CLI 0.166.0, captured on 2026-11-16. Claude 2.1.0
was executed from its official, pinned npm package. Each has missing, owned
Python stdio, and unrelated Node stdio cases.

Claude used the documented `CLAUDE_CONFIG_DIR` in a private temporary directory;
Codex used in-memory `-c mcp_servers.<fixture>.command=...` and `.args=...`
overrides. Personal configuration was not edited. Only fixture names, paths,
command and scope values are replaced by placeholders. Other fields and wording
come from the CLI responses. The tests substitute runtime fixture values while
preserving the captured response shape.

The dummy command points at an absent fixture server, so its connection-status
line does not establish MCP readiness. These captures validate CLI parsing;
the separate SDK and target-chat proofs validate messaging and runtime loading.
