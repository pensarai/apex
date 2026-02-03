/**
 * ReportGeneratorAgent
 *
 * Generates comprehensive penetration testing reports from session findings.
 */

export { generatePentestReport } from './agent';

export type {
  ReportGeneratorInput,
  ReportGeneratorResult,
  Finding,
  FindingsCount,
} from './types';
