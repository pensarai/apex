/**
 * Shared types for the email tool suite.
 *
 * The tools support three providers (gmail, outlook, imap) with a
 * unified interface — provider-specific logic lives in the adapters.
 */

export interface EmailMessageSummary {
  id: string;
  from: string;
  to: string[];
  subject: string;
  date: string;
  snippet: string;
  isRead: boolean;
  hasAttachments: boolean;
  labels?: string[];
}

export interface EmailMessageFull extends EmailMessageSummary {
  body: string;
  cc?: string[];
  bcc?: string[];
  replyTo?: string;
  headers?: Record<string, string>;
}

export interface EmailAttachment {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
}

export interface EmailListResult {
  messages: EmailMessageSummary[];
  nextPageToken?: string;
  totalEstimate?: number;
}

export interface EmailSearchResult {
  messages: EmailMessageSummary[];
  nextPageToken?: string;
  totalEstimate?: number;
}
