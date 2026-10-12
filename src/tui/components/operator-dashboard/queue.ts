/**
 * Pure utility functions for queued-message state management.
 * Extracted for testability — consumed by the OperatorDashboard keyboard handler.
 */

export interface QueuedMessage {
  id: number;
  text: string;
}

let nextId = 0;

export function createQueuedMessage(text: string): QueuedMessage {
  return { id: nextId++, text };
}

/**
 * Compute the next selectedIndex after deleting the item at `removedIndex`.
 */
export function selectionAfterRemove(
  prevQueueLength: number,
  selectedIndex: number,
): number {
  const newLen = prevQueueLength - 1;
  if (newLen === 0) return -1;
  return Math.min(selectedIndex, newLen - 1);
}

/**
 * Navigate **up** within the queue.
 * - From input (-1) → last queue item (enter queue).
 * - From first item (0) → stay at 0.
 * - Otherwise → prev - 1.
 */
export function navigateUp(selectedIndex: number, queueLength: number): number {
  if (queueLength === 0) return -1;
  if (selectedIndex === -1) return queueLength - 1;
  if (selectedIndex === 0) return 0;
  return selectedIndex - 1;
}

/**
 * Navigate **down** within the queue.
 * - From the last item → -1 (exit queue, back to input).
 * - Otherwise → prev + 1.
 * - From input (-1) → stay at -1 (no-op, handled by caller).
 */
export function navigateDown(
  selectedIndex: number,
  queueLength: number,
): number {
  if (selectedIndex === -1) return -1;
  if (selectedIndex >= queueLength - 1) return -1;
  return selectedIndex + 1;
}
