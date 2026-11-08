/** Stable answer when a send may already have reached Relaycast. The same clientMessageId is not dispatched again. */
export const SEND_UNCERTAIN_MESSAGE =
  "The relay did not confirm the message. It may have been delivered. This clientMessageId will not be sent again.";

export class MessagingHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "MessagingHttpError";
  }
}

/** Test hook: the send claim stays pending, as it would after a process crash. */
export class SendAbandoned extends Error {
  constructor() {
    super("send abandoned before the local result was committed");
    this.name = "SendAbandoned";
  }
}
