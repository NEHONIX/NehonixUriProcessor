import { ShieldRule, RuleType, ActionType, ConditionType } from "./types/ShieldTypes";
import * as fs from 'fs';
import * as path from 'path';

class NSHSyntaxError extends Error {
  constructor(
    message: string,
    public readonly line: number,
    public readonly column: number,
    public readonly filePath?: string
  ) {
    super(
      `${message}\n  at line ${line}${column ? `, column ${column}` : ''}${filePath ? `\n  in ${filePath}` : ''}`
    );
    this.name = 'NSHSyntaxError';
  }
}

export class NSHParser {
  private static readonly RULE_SEPARATOR = "---";
  private static readonly COMMENT_PREFIX = "#";
  private static readonly KNOWN_PROPERTIES = ['type', 'priority', 'condition', 'action'];
  private static readonly KNOWN_TYPES = Object.values(RuleType);
  private static readonly KNOWN_CONDITION_TYPES = Object.values(ConditionType);
  private static readonly KNOWN_ACTION_TYPES = Object.values(ActionType);

  /**
   * Parse a .nsh file into ShieldRules
   * Example .nsh file format:
   * 
   * # CSP Rule
   * type: csp
   * priority: 100
   * condition:
   *   type: match_path
   *   value: /api/*
   * action:
   *   type: modify
   *   value:
   *     directive: script-src
   *     sources: ['https://api.example.com']
   * ---
   * # CSRF Rule
   * type: csrf
   * priority: 90
   * condition:
   *   type: match_path
   *   value: /public/*
   * action:
   *   type: allow
   */

  public static parseFile(filePath: string): ShieldRule[] {
    if (!filePath.endsWith('.nsh')) {
      throw new Error('Invalid file extension. Only .nsh files are supported.');
    }

    const content = fs.readFileSync(filePath, 'utf8');
    return this.parseContent(content);
  }

  public static parseContent(content: string, filePath?: string): ShieldRule[] {
    const rules: ShieldRule[] = [];
    const ruleBlocks = content.split(this.RULE_SEPARATOR);
    let currentLine = 1;

    for (const block of ruleBlocks) {
      if (!block.trim()) {
        currentLine += block.split('\n').length;
        continue;
      }

      const lines = block.split('\n');
      const blockStartLine = currentLine;
      
      try {
        const filteredLines = lines
          .map((line, idx) => ({ 
            content: line.trim(),
            originalLine: blockStartLine + idx,
            indentation: line.length - line.trimLeft().length
          }))
          .filter(line => line.content && !line.content.startsWith(this.COMMENT_PREFIX));

        const rule = this.parseRuleBlock(filteredLines, filePath);
        rules.push(rule);
      } catch (error) {
        if (error instanceof NSHSyntaxError) {
          console.error(error.message);
        } else {
          console.error(`Unexpected error in rule block starting at line ${blockStartLine}${filePath ? ` in ${filePath}` : ''}`);
        }
      }

      currentLine += lines.length;
    }

    return rules;
  }

  private static parseRuleBlock(lines: { content: string; originalLine: number; indentation: number }[], filePath?: string): ShieldRule {
    let currentRule: Partial<ShieldRule> = {
      id: crypto.randomUUID()
    };
    let currentSection: string | null = null;
    let currentObject: any = {};

    for (const { content: line, originalLine, indentation } of lines) {
      if (line.includes(':')) {
        const [key, value] = line.split(':').map(part => part.trim());

        // Validate known properties
        if (!currentSection && !this.KNOWN_PROPERTIES.includes(key)) {
          throw new NSHSyntaxError(
            `Unknown property '${key}'. Expected one of: ${this.KNOWN_PROPERTIES.join(', ')}`,
            originalLine,
            indentation + 1,
            filePath
          );
        }

        if (['condition', 'action'].includes(key)) {
          if (indentation !== 0) {
            throw new NSHSyntaxError(
              `Invalid indentation for section '${key}'. Must be at root level`,
              originalLine,
              1,
              filePath
            );
          }
          currentSection = key;
          currentObject = {};
          continue;
        }

        if (currentSection) {
          currentObject[key] = this.parseValue(value, originalLine, indentation, filePath);
        } else {
          currentRule[key as keyof ShieldRule] = this.parseValue(value, originalLine, indentation, filePath);
        }
      }

      if (currentSection && Object.keys(currentObject).length > 0) {
        currentRule[currentSection as keyof ShieldRule] = currentObject;
      }
    }

    return this.validateRule(currentRule as ShieldRule);
  }

  private static parseValue(value: string, line: number, column: number, filePath?: string): any {
    if (value.startsWith('[') && value.endsWith(']')) {
      return value.slice(1, -1).split(',').map(v => v.trim());
    }

    if (value.startsWith('{') && value.endsWith('}')) {
      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    }

    if (value === 'true') return true;
    if (value === 'false') return false;
    if (!isNaN(Number(value))) return Number(value);

    return value;
  }

  private static validateRule(rule: ShieldRule, filePath?: string): ShieldRule {
    if (!rule.type || !this.KNOWN_TYPES.includes(rule.type as RuleType)) {
      throw new NSHSyntaxError(
        `Invalid rule type: '${rule.type}'. Expected one of: ${this.KNOWN_TYPES.join(', ')}`,
        0, 0, filePath
      );
    }

    if (!rule.priority || typeof rule.priority !== 'number') {
      throw new NSHSyntaxError(
        'Priority must be a number',
        0, 0, filePath
      );
    }

    if (!rule.condition || !rule.condition.type || !this.KNOWN_CONDITION_TYPES.includes(rule.condition.type as ConditionType)) {
      throw new NSHSyntaxError(
        `Invalid condition type: '${rule.condition?.type}'. Expected one of: ${this.KNOWN_CONDITION_TYPES.join(', ')}`,
        0, 0, filePath
      );
    }

    if (!rule.action || !rule.action.type || !this.KNOWN_ACTION_TYPES.includes(rule.action.type as ActionType)) {
      throw new NSHSyntaxError(
        `Invalid action type: '${rule.action?.type}'. Expected one of: ${this.KNOWN_ACTION_TYPES.join(', ')}`,
        0, 0, filePath
      );
    }

    return rule;
  }

  public static async loadDirectory(dirPath: string): Promise<ShieldRule[]> {
    const rules: ShieldRule[] = [];
    const files = await fs.promises.readdir(dirPath);

    for (const file of files) {
      if (file.endsWith('.nsh')) {
        const filePath = path.join(dirPath, file);
        const fileRules = this.parseFile(filePath);
        rules.push(...fileRules);
      }
    }

    return rules;
  }
}
