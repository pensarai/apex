/**
 * Types for ReportGeneratorAgent
 */

import type { CVSS4Metrics } from '../../../lib/cvss';

/** CVSS 4.0 score data attached to a finding */
export interface FindingCVSSData {
  /** Numeric score (0.0-10.0) */
  score: number;
  /** Qualitative severity (NONE, LOW, MEDIUM, HIGH, CRITICAL) */
  severity: string;
  /** Full vector string (CVSS:4.0/AV:N/...) */
  vectorString: string;
  /** Individual metric values */
  metrics: CVSS4Metrics;
  /** Score type (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE) */
  scoreType: string;
  /** AI's reasoning for metric choices */
  reasoning: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  impact: string;
  evidence: string;
  endpoint: string;
  pocPath: string;
  remediation: string;
  references?: string;
  timestamp: string;
  sessionId: string;
  target: string;
  vulnerabilityClass?: string;
  /** CVSS 4.0 score data (if scoring was enabled) */
  cvss?: FindingCVSSData;
}

export interface ReportGeneratorInput {
  /** Session root path */
  sessionRootPath: string;

  /** Session ID */
  sessionId: string;

  /** Main target */
  target: string;

  /** Session start time */
  startTime?: string;

  /** Session end time */
  endTime?: string;

  /** Custom report title */
  reportTitle?: string;

  /** Include detailed methodology section */
  includeMethodology?: boolean;
}

export interface ReportGeneratorResult {
  success: boolean;
  reportPath?: string;
  reportContent?: string;
  findingsCount: FindingsCount;
  error?: string;
}

export interface FindingsCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  /** CVSS 4.0 statistics (if any findings have CVSS scores) */
  cvss?: {
    averageScore: number;
    maxScore: number;
    byRange: {
      critical: number;  // 9.0-10.0
      high: number;      // 7.0-8.9
      medium: number;    // 4.0-6.9
      low: number;       // 0.1-3.9
      none: number;      // 0.0
    };
  };
}
