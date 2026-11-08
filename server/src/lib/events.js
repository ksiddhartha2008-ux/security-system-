import { EventEmitter } from 'node:events';

/** In-process event bus used by the SSE stream (monitoring + simulations). */
export const bus = new EventEmitter();
bus.setMaxListeners(100);

export function broadcast(orgId, event, payload) {
  bus.emit('org', { orgId, event, payload });
}
