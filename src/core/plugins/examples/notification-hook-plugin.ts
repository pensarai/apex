/**
 * Example Hook Plugin: Notification System
 * 
 * This plugin demonstrates how to create a hook plugin that
 * responds to events in the Pensar lifecycle.
 */

import { createHookPlugin, type HookEvent } from '../index';

/**
 * Notification configuration
 */
interface NotificationConfig {
  // Console notifications
  console: boolean;
  // Webhook URL for external notifications
  webhookUrl?: string;
  // Slack webhook URL
  slackWebhookUrl?: string;
  // Minimum severity for notifications
  minSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

/**
 * Default configuration
 */
const defaultConfig: NotificationConfig = {
  console: true,
  minSeverity: 'medium',
};

/**
 * Get config from environment
 */
function getConfig(): NotificationConfig {
  return {
    ...defaultConfig,
    webhookUrl: process.env.PENSAR_NOTIFICATION_WEBHOOK,
    slackWebhookUrl: process.env.PENSAR_SLACK_WEBHOOK,
    minSeverity: (process.env.PENSAR_NOTIFICATION_MIN_SEVERITY as any) || defaultConfig.minSeverity,
  };
}

/**
 * Severity levels for comparison
 */
const SEVERITY_LEVELS = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Check if severity meets minimum threshold
 */
function meetsMinSeverity(severity: string, minSeverity: string): boolean {
  const severityLevel = SEVERITY_LEVELS[severity as keyof typeof SEVERITY_LEVELS] || 0;
  const minLevel = SEVERITY_LEVELS[minSeverity as keyof typeof SEVERITY_LEVELS] || 0;
  return severityLevel >= minLevel;
}

/**
 * Send notification to console
 */
function notifyConsole(title: string, message: string, severity?: string): void {
  const timestamp = new Date().toISOString();
  const severityTag = severity ? `[${severity.toUpperCase()}]` : '';
  console.log(`[NOTIFICATION] ${timestamp} ${severityTag} ${title}`);
  console.log(`  ${message}`);
}

/**
 * Send notification to webhook
 */
async function notifyWebhook(
  url: string,
  payload: {
    event: HookEvent;
    title: string;
    message: string;
    severity?: string;
    data?: any;
  }
): Promise<void> {
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...payload,
        timestamp: new Date().toISOString(),
        source: 'pensar',
      }),
    });
  } catch (error) {
    console.error('Failed to send webhook notification:', error);
  }
}

/**
 * Send notification to Slack
 */
async function notifySlack(
  webhookUrl: string,
  title: string,
  message: string,
  severity?: string
): Promise<void> {
  const color = severity === 'critical' ? '#FF0000' :
                severity === 'high' ? '#FF6600' :
                severity === 'medium' ? '#FFCC00' :
                severity === 'low' ? '#00CC00' : '#808080';

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        attachments: [{
          color,
          title,
          text: message,
          footer: 'Pensar Security Scanner',
          ts: Math.floor(Date.now() / 1000),
        }],
      }),
    });
  } catch (error) {
    console.error('Failed to send Slack notification:', error);
  }
}

/**
 * Send notification through all configured channels
 */
async function notify(
  event: HookEvent,
  title: string,
  message: string,
  severity?: string,
  data?: any
): Promise<void> {
  const config = getConfig();

  // Check severity threshold
  if (severity && !meetsMinSeverity(severity, config.minSeverity)) {
    return;
  }

  // Console notification
  if (config.console) {
    notifyConsole(title, message, severity);
  }

  // Webhook notification
  if (config.webhookUrl) {
    await notifyWebhook(config.webhookUrl, { event, title, message, severity, data });
  }

  // Slack notification
  if (config.slackWebhookUrl) {
    await notifySlack(config.slackWebhookUrl, title, message, severity);
  }
}

/**
 * Notification Hook Plugin
 */
export const notificationPlugin = createHookPlugin({
  metadata: {
    id: 'pensar-notifications',
    name: 'Notification System',
    version: '1.0.0',
    description: 'Send notifications for Pensar events to various channels',
    author: 'Pensar',
    tags: ['notifications', 'slack', 'webhook', 'alerts'],
  },
  hooks: {
    /**
     * Session started
     */
    'session:start': async (data: any) => {
      await notify(
        'session:start',
        'Security Scan Started',
        `New scan session started for ${data.targets?.length || 0} targets`,
        'info',
        data
      );
    },

    /**
     * Session ended
     */
    'session:end': async (data: any) => {
      const severity = data.findingsCount > 0 ? 
        (data.criticalCount > 0 ? 'critical' : 'high') : 'info';
      
      await notify(
        'session:end',
        'Security Scan Complete',
        `Scan complete: ${data.findingsCount || 0} findings discovered`,
        severity,
        data
      );
    },

    /**
     * Finding discovered
     */
    'finding:discovered': async (data: any) => {
      await notify(
        'finding:discovered',
        `Finding: ${data.title || 'Security Issue'}`,
        data.description || 'A security vulnerability was discovered',
        data.severity || 'medium',
        data
      );
    },

    /**
     * Agent started
     */
    'agent:start': async (data: any) => {
      await notify(
        'agent:start',
        'Agent Started',
        `Agent ${data.agent || 'unknown'} started testing ${data.target || 'target'}`,
        'info',
        data
      );
    },

    /**
     * Agent completed
     */
    'agent:end': async (data: any) => {
      const message = data.error 
        ? `Agent ${data.agent || 'unknown'} failed: ${data.error}`
        : `Agent ${data.agent || 'unknown'} completed with ${data.findingsCount || 0} findings`;
      
      await notify(
        'agent:end',
        'Agent Completed',
        message,
        data.error ? 'high' : 'info',
        data
      );
    },

    /**
     * Test started
     */
    'test:start': async (data: any) => {
      await notify(
        'test:start',
        'Test Started',
        `Testing ${data.vulnerabilityClass || 'vulnerability'} on ${data.target || 'target'}`,
        'info',
        data
      );
    },

    /**
     * Test completed
     */
    'test:end': async (data: any) => {
      if (data.vulnerable) {
        await notify(
          'test:end',
          'Vulnerability Confirmed',
          `${data.vulnerabilityClass || 'Vulnerability'} confirmed on ${data.target || 'target'}`,
          data.severity || 'high',
          data
        );
      }
    },
  },
  
  onLoad: async () => {
    const config = getConfig();
    console.log('Notification plugin loaded');
    console.log(`  Console notifications: ${config.console ? 'enabled' : 'disabled'}`);
    console.log(`  Webhook: ${config.webhookUrl ? 'configured' : 'not configured'}`);
    console.log(`  Slack: ${config.slackWebhookUrl ? 'configured' : 'not configured'}`);
    console.log(`  Minimum severity: ${config.minSeverity}`);
  },
});

export default notificationPlugin;
