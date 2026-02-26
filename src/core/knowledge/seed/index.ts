/**
 * Seed Knowledge Loader
 *
 * Exports the path to the bundled seed techniques directory
 * so the store can load them on startup.
 */

import { join } from "path";

/** Absolute path to the seed techniques directory */
export const SEED_TECHNIQUES_DIR = join(__dirname, "techniques");
