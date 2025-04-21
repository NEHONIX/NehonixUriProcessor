import chalk from "chalk";

type LogLevel = "error" | "warn" | "info" | "debug" | "verbose" | "silly";
type LogType = "error" | "info" | "warn" | "debug" | "table" | "log";

// Define allowed chalk colors more precisely
type ChalkColorName = keyof typeof chalk;

interface LoggerOptions {
  level?: LogLevel;
  timestamp?: boolean;
  timestampFormat?: "iso" | "locale" | "time";
  prefix?: string;
  colorize?: boolean;
}

export class AppLogger {
  private static logLevels: Record<LogLevel, number> = {
    error: 0,
    warn: 1,
    info: 2,
    debug: 3,
    verbose: 4,
    silly: 5,
  };

  private static currentLevel: LogLevel = "info";
  private static options: LoggerOptions = {
    timestamp: true,
    timestampFormat: "iso",
    colorize: true,
    prefix: "",
  };
  static debugs_state = false;
  /**
   * Configure logger options
   */
  static configure(options: LoggerOptions): void {
    this.options = { ...this.options, ...options };
    if (options.level) {
      this.currentLevel = options.level;
    }
  }

  /**
   * Format timestamp based on configuration
   */
  private static formatTimestamp(): string {
    if (!this.options.timestamp) return "";

    const now = new Date();
    let timestamp = "";

    switch (this.options.timestampFormat) {
      case "iso":
        timestamp = now.toISOString();
        break;
      case "locale":
        timestamp = now.toLocaleString();
        break;
      case "time":
        timestamp = now.toLocaleTimeString();
        break;
      default:
        timestamp = now.toISOString();
    }

    return `[${timestamp}]`;
  }

  /**
   * Apply chalk color safely
   */
  private static applyColor(text: string, colorName: ChalkColorName): string {
    // Make sure the color exists on chalk
    if (typeof chalk[colorName] === "function") {
      return (chalk[colorName] as any)(text);
    }
    // Fallback to no color
    return text;
  }

  /**
   * Core logging method
   */
  static appLog(props: {
    messages: any[];
    type: LogType;
    level: LogLevel;
    colorName: ChalkColorName;
  }): void {
    // Check if this log should be shown based on level
    if (this.logLevels[props.level] > this.logLevels[this.currentLevel]) {
      return;
    }

    const timestamp = this.formatTimestamp();
    const prefix = this.options.prefix ? `[${this.options.prefix}]` : "";
    const levelTag = `[${props.level.toUpperCase()}]`;

    let formattedMessages = [...props.messages];

    // Apply color if enabled
    if (this.options.colorize) {
      // Only colorize strings, leave objects and other types as-is
      formattedMessages = formattedMessages.map((msg) =>
        typeof msg === "string" ? this.applyColor(msg, props.colorName) : msg
      );

      // Add colored prefix
      const headerParts = [timestamp, prefix, levelTag]
        .filter(Boolean)
        .join(" ");
      if (headerParts) {
        formattedMessages.unshift(
          this.applyColor(headerParts, props.colorName)
        );
      }
    } else {
      // No color, just add prefix
      const headerParts = [timestamp, prefix, levelTag]
        .filter(Boolean)
        .join(" ");
      if (headerParts) {
        formattedMessages.unshift(headerParts);
      }
    }

    // Use appropriate console method
    if (this.debugs_state) {
      if (props.type === "table" && Array.isArray(props.messages[0])) {
        console.table(props.messages[0]);
      } else {
        console[props.type](...formattedMessages);
      }
    }
  }

  /**
   * Log an informational message
   */
  static log(...messages: any[]): void {
    this.appLog({
      messages,
      type: "log",
      level: "info",
      colorName: "green",
    });
  }

  /**
   * Log an informational message
   */
  static info(...messages: any[]): void {
    this.appLog({
      messages,
      type: "info",
      level: "info",
      colorName: "green",
    });
  }

  /**
   * Log a warning message
   */
  static warn(...messages: any[]): void {
    this.appLog({
      messages,
      type: "warn",
      level: "warn",
      colorName: "yellow",
    });
  }

  /**
   * Log an error message
   */
  static error(...messages: any[]): void {
    this.appLog({
      messages,
      type: "error",
      level: "error",
      colorName: "red",
    });
  }

  /**
   * Log a debug message
   */
  static debug(...messages: any[]): void {
    this.appLog({
      messages,
      type: "debug",
      level: "debug",
      colorName: "blue",
    });
  }

  /**
   * Log a verbose message
   */
  static verbose(...messages: any[]): void {
    this.appLog({
      messages,
      type: "log",
      level: "verbose",
      colorName: "magenta",
    });
  }

  /**
   * Log detailed or silly debug information
   */
  static silly(...messages: any[]): void {
    this.appLog({
      messages,
      type: "log",
      level: "silly",
      colorName: "gray",
    });
  }

  /**
   * Log data as a table
   */
  static table(tableData: any[], columns?: string[]): void {
    this.appLog({
      messages: [tableData, columns],
      type: "table",
      level: "info",
      colorName: "cyan",
    });
  }

  /**
   * Log start of a process with a title
   */
  static start(title: string): void {
    this.appLog({
      messages: [`▶ ${title}`],
      type: "info",
      level: "info",
      colorName: "cyan",
    });
  }

  /**
   * Log successful completion of a process
   */
  static success(message: string): void {
    this.appLog({
      messages: [`✅ ${message}`],
      type: "info",
      level: "info",
      colorName: "green",
    });
  }

  /**
   * Log failure of a process
   */
  static fail(message: string): void {
    this.appLog({
      messages: [`❌ ${message}`],
      type: "error",
      level: "error",
      colorName: "red",
    });
  }
}
