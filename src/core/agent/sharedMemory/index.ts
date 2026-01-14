/**
 * Shared Memory Module
 *
 * Provides a shared memory system for tracking approach outcomes
 * across all testing agents in a session.
 */

export {
  SharedMemoryFileStore,
  buildSharedMemoryContext,
} from './sharedMemoryStore';

export type {
  SharedApproach,
  SharedApproachInput,
  SharedMemoryFilter,
  SharedMemoryStore,
  SharedMemorySummary,
  RelevantApproachesResult,
} from './types';
