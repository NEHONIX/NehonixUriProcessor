import { Request } from "express";

export interface ShieldRule {
  id: string;
  type: RuleType;
  priority: number;
  condition: RuleCondition;
  action: RuleAction;
}

export enum RuleType {
  CSP = "csp",
  CSRF = "csrf",
  COOKIE = "cookie",
  REQUEST = "request",
  IP = "ip",
  HEADER = "header",
  ML = "ml"
}

export interface MLPrediction {
  probability: number;
  classification: string;
  confidence: number;
  threat_types: string[];
  top_features: Array<{
    name: string;
    contribution: number;
    value: number;
  }>;
}

export interface MLRuleConfig {
  threshold: number;
  action: string;
  model_version?: string;
  threat_types?: string[];
}

export interface RuleCondition {
  type: ConditionType;
  value: any;
}

export enum ConditionType {
  MATCH_PATH = "match_path",
  MATCH_METHOD = "match_method",
  MATCH_IP = "match_ip",
  MATCH_HEADER = "match_header",
  CUSTOM = "custom"
}

export interface RuleAction {
  type: ActionType;
  value: any;
}

export enum ActionType {
  ALLOW = "allow",
  DENY = "deny",
  MODIFY = "modify",
  ADD_HEADER = "add_header",
  REMOVE_HEADER = "remove_header"
}

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  domain?: string;
  path?: string;
  maxAge?: number;
}
