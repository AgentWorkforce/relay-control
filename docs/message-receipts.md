# Message delivery receipts over MCP

After `send_relay_message`, call `get_relay_message_status` with its
`message_id`. Both self-hosted and Cloud MCP expose the same arguments:
`message_id`, optional `as` for your own sending participant, and optional
`as_person` for an explicit Cloud person send (refused on self-hosted sites).
OAuth uses
only its approved agent. A receipt lookup never uses a workspace key.

The response includes `message_id`, `you`, `confirmation`, `deliveries` and
`note`. `confirmation: available` means the engine returned receipt data,
not that the message arrived. Inspect each delivery's `state`:

| State | Meaning |
| --- | --- |
| queued | Waiting; a socket write alone does not confirm acceptance |
| delivered | Recipient software durably accepted the message |
| consumed | Recipient acknowledged the delivery |
| replied | An explicitly correlated reply exists; see `reply_message_id` |
| failed | Delivery failed; arbitrary upstream error details are withheld |

`read_at` records an explicit read receipt only. Acknowledgement does not
mean a person read the message or a model understood it. An empty list does
not confirm delivery.

The engine must include Relaycast #625's delivery-confirmation API and its
migrations. Older engines, unknown messages and messages not visible as your
own outgoing message return `confirmation: unavailable`, an empty delivery
list and an unconfirmed note on 404/501. Other authorization failures and
outages remain errors. Do not resend solely because confirmation is absent.
Send responses retain `queued_unconfirmed` / `queued_offline` for compatibility;
use this lookup for current receipt state.
