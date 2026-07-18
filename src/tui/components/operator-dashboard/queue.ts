/**
 * Pure utility functions for queued-message state management.
 * Extracted for testability — consumed by the OperatorDashboard keyboard handler.
 */

export interface QueuedMessage {
  id: number;
  text: string;
}

export interface QueueWindowItem {
  index: number;
  message: QueuedMessage;
}

export interface QueueWindow {
  end: number;
  items: QueueWindowItem[];
  start: number;
}

let nextId = 0;

export function createQueuedMessage(text: string): QueuedMessage {
  return { id: nextId++, text };
}

/** Add a message to the end of the queue. */
export function queueAdd(
  queue: QueuedMessage[],
  message: string,
): QueuedMessage[] {
  return [...queue, createQueuedMessage(message)];
}

/** Remove the item at `index` and return the new queue. */
export function queueRemove(
  queue: QueuedMessage[],
  index: number,
): QueuedMessage[] {
  return queue.filter((_, i) => i !== index);
}

/**
 * Clamp or reset `selectedIndex` after the queue changes size.
 * Returns -1 (deselected) when the queue is empty.
 */
export function clampQueueSelection(
  queueLength: number,
  selectedIndex: number,
): number {
  if (queueLength === 0) return -1;
  if (selectedIndex >= queueLength) return queueLength - 1;
  return selectedIndex;
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

export function getQueueWindow(
  queue: QueuedMessage[],
  selectedIndex: number,
  maxVisible = 3,
): QueueWindow {
  if (queue.length === 0 || maxVisible <= 0) {
    return { start: 0, end: 0, items: [] };
  }

  const size = Math.min(maxVisible, queue.length);
  const anchor =
    selectedIndex >= 0 && selectedIndex < queue.length
      ? selectedIndex
      : queue.length - 1;
  const start = Math.max(
    0,
    Math.min(anchor - Math.floor(size / 2), queue.length - size),
  );
  const end = start + size;

  return {
    start,
    end,
    items: queue.slice(start, end).map((message, offset) => ({
      index: start + offset,
      message,
    })),
  };
}
