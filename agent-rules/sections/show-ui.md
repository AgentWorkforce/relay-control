Use Agent Relay's `show_ui` for dashboards, charts, status boards, plans,
timelines and interactive views. Share the returned `view_url`, and keep its
`canvas_id` so the same live canvas can stay current.

When a visual would help, or a relay message contains a fenced `relay-ui`
block, call `show_ui` with the spec. Read `show_ui_guide` first for the current
block types and fields; it changes over time. Give the person the returned
`view_url` as a link so they can open the visual in their browser.

For the everyday questions, use these presets:
"status?" or "what's going on?" is `show_ui` with `{"preset": "status_board"}`;
"which agents are where?" is `fleet` (add `{"options": {"machine": "<name>"}}`
for one machine); "did the run work?" is `runs`; "what got done today?" is
`recap`; "how is the team using agents?" is `usage`; "where are agents
working?" is `projects` (add `{"options": {"project": "<name>"}}` for one);
"what did agents ship?" is `shipped`. Presets are filled by the server from
what Agent Relay records (agent sessions, the relay roster, flow runs), so
they work without any other connection.

When the result says `live: true`, that link is a live screen. Keep its
`canvas_id`: when the person asks to see something different, or new data
arrives, call `show_ui` again with the same `canvas_id` and the full new spec.
The page they have open updates by itself, so say what changed. Start a new
screen (no `canvas_id`) only when they ask for a separate one. When they want
it on their dashboard, pass
`add_to_board: true`: it becomes a tab on their Agent Relay Sessions board and
an open board switches to it.
