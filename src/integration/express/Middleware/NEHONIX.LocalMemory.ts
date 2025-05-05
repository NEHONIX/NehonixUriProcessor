import { SecurityDatabaseAdapterType } from "../../types/types.express.middleware";
import { SecurityEvent } from "../../types/types.express.middleware";

// NLM => Nehonix Local Memory
/**
 * In-memory database adapter (default)
 */
export class NLM implements SecurityDatabaseAdapterType {
  private suspiciousIPs: Map<
    string,
    { count: number; lastSeen: number; details?: any }
  > = new Map();
  private blockedIPs: Set<string> = new Set();
  private securityEvents: SecurityEvent[] = [];

  async trackSuspiciousIP(ip: string, details: any): Promise<void> {
    const now = Date.now();
    const record = this.suspiciousIPs.get(ip);

    if (record) {
      // Update existing record
      record.count += 1;
      record.lastSeen = now;
      record.details = { ...record.details, ...details };
    } else {
      // Create new record
      this.suspiciousIPs.set(ip, { count: 1, lastSeen: now, details });
    }

    // Cleanup old records every 100 entries
    if (this.suspiciousIPs.size % 100 === 0) {
      this.cleanupSuspiciousIPs();
    }
  }

  async getSuspiciousIPs(): Promise<
    Array<{ ip: string; count: number; lastSeen: number; details?: any }>
  > {
    return Array.from(this.suspiciousIPs.entries()).map(([ip, data]) => ({
      ip,
      count: data.count,
      lastSeen: data.lastSeen,
      details: data.details,
    }));
  }

  async blockIP(ip: string, reason: string): Promise<boolean> {
    this.blockedIPs.add(ip);

    // Add a security event
    await this.saveSecurityEvent({
      timestamp: Date.now(),
      type: "block",
      ip,
      details: { reason },
    });

    return true;
  }

  async isIPBlocked(ip: string): Promise<boolean> {
    return this.blockedIPs.has(ip);
  }

  async saveSecurityEvent(event: SecurityEvent): Promise<void> {
    this.securityEvents.push(event);

    // Keep only the last 10,000 events
    if (this.securityEvents.length > 10000) {
      this.securityEvents = this.securityEvents.slice(-10000);
    }
  }

  async getSecurityEvents(options: {
    startDate: Date;
    endDate: Date;
  }): Promise<SecurityEvent[]> {
    const startTime = options.startDate.getTime();
    const endTime = options.endDate.getTime();

    return this.securityEvents.filter(
      (event) => event.timestamp >= startTime && event.timestamp <= endTime
    );
  }

  private cleanupSuspiciousIPs(): void {
    const now = Date.now();
    const expirationTime = 24 * 60 * 60 * 1000; // 24 hours

    for (const [ip, record] of this.suspiciousIPs.entries()) {
      if (now - record.lastSeen > expirationTime) {
        this.suspiciousIPs.delete(ip);
      }
    }
  }
}

// Default in-memory database
export const defaultDatabase = new NLM();

// Current active database adapter
export let activeDatabase: SecurityDatabaseAdapterType = defaultDatabase;

/**
 * Set a custom database adapter
 */
export function setDatabaseAdapter(adapter: SecurityDatabaseAdapterType): void {
  activeDatabase = adapter;
}

/**
 * Get the current database adapter
 */
export function getDatabaseAdapter(): SecurityDatabaseAdapterType {
  return activeDatabase;
}

export { NLM as InMemoryDatabaseAdapter };
