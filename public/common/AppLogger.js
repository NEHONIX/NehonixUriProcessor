import chalk from "chalk";
export class AppLogger {
    /**
     * Configure logger options
     */
    static configure(options) {
        this.options = { ...this.options, ...options };
        if (options.level) {
            this.currentLevel = options.level;
        }
    }
    /**
     * Format timestamp based on configuration
     */
    static formatTimestamp() {
        if (!this.options.timestamp)
            return "";
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
    static applyColor(text, colorName) {
        // Make sure the color exists on chalk
        if (typeof chalk[colorName] === "function") {
            return chalk[colorName](text);
        }
        // Fallback to no color
        return text;
    }
    /**
     * Core logging method
     */
    static appLog(props) {
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
            formattedMessages = formattedMessages.map((msg) => typeof msg === "string" ? this.applyColor(msg, props.colorName) : msg);
            // Add colored prefix
            const headerParts = [timestamp, prefix, levelTag]
                .filter(Boolean)
                .join(" ");
            if (headerParts) {
                formattedMessages.unshift(this.applyColor(headerParts, props.colorName));
            }
        }
        else {
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
            }
            else {
                console[props.type](...formattedMessages);
            }
        }
    }
    /**
     * Log an informational message
     */
    static log(...messages) {
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
    static info(...messages) {
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
    static warn(...messages) {
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
    static error(...messages) {
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
    static debug(...messages) {
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
    static verbose(...messages) {
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
    static silly(...messages) {
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
    static table(tableData, columns) {
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
    static start(title) {
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
    static success(message) {
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
    static fail(message) {
        this.appLog({
            messages: [`❌ ${message}`],
            type: "error",
            level: "error",
            colorName: "red",
        });
    }
}
AppLogger.logLevels = {
    error: 0,
    warn: 1,
    info: 2,
    debug: 3,
    verbose: 4,
    silly: 5,
};
AppLogger.currentLevel = "info";
AppLogger.options = {
    timestamp: true,
    timestampFormat: "iso",
    colorize: true,
    prefix: "",
};
AppLogger.debugs_state = true;
//# sourceMappingURL=AppLogger.js.map