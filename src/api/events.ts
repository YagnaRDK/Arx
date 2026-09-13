/**
 * In-process event bus for the security cockpit's live feed.
 *
 * Deliberately fire-and-forget and deliberately not on the decision path: a
 * dashboard subscriber must never be able to slow down, block, or fail an
 * authorization. Publishing catches and discards subscriber errors for the same
 * reason, and the buffer is bounded so a stalled client cannot grow memory
 * without limit.
 */

export type ArxEvent = {
  seq: number;
  type: string;
  at: number;
  data: Record<string, unknown>;
};

type Subscriber = (event: ArxEvent) => void;

const MAX_BUFFER = 200;

export class EventBus {
  private seq = 0;
  private readonly subscribers = new Set<Subscriber>();
  private readonly recent: ArxEvent[] = [];

  publish(type: string, data: Record<string, unknown> = {}): ArxEvent {
    this.seq += 1;

    const event: ArxEvent = {
      seq: this.seq,
      type,
      at: Date.now(),
      data,
    };

    this.recent.push(event);

    if (this.recent.length > MAX_BUFFER) {
      this.recent.shift();
    }

    for (const subscriber of this.subscribers) {
      try {
        subscriber(event);
      } catch {
        // A broken subscriber is the subscriber's problem, never the
        // authorization's.
      }
    }

    return event;
  }

  subscribe(subscriber: Subscriber): () => void {
    this.subscribers.add(subscriber);
    return () => this.subscribers.delete(subscriber);
  }

  /** Replayed to a new subscriber so a freshly opened dashboard is not blank. */
  backlog(limit = 50): ArxEvent[] {
    return this.recent.slice(-limit);
  }

  get subscriberCount(): number {
    return this.subscribers.size;
  }
}

export const eventBus = new EventBus();
