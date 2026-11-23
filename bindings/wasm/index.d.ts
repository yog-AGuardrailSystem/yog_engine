export type Decision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";

export interface ObligationArg {
  kind?: string;
  value?: string | number | boolean;
}

export interface Obligation {
  name: string;
  args: Array<string | number | boolean>;
}

export interface CheckResult {
  decision: Decision;
  reason: string;
  obligations: Obligation[];
  matched_line?: number;
  trace?: string;
  /** Present when the request could not be evaluated; `decision` is then always "DENY". */
  error?: { message: string; line?: number; column?: number };
}

export interface Request {
  actor: string;
  action: string;
  resource: string;
  args?: Record<string, unknown>;
  env?: Record<string, unknown>;
  state?: { version: number; values: Record<string, unknown> };
  now?: number;
  facts?: Array<{ predicate: string; args: Array<string | number | boolean> }>;
  request_id?: string;
}

export class CompileError extends Error {
  line: number;
  column: number;
  detail: string;
}

export class Policy {
  /** Checks one request; never throws for a bad request (returns a DENY with `error`). */
  checkJson(request: Request | string, options?: { trace?: boolean }): CheckResult;
  readonly policyVersion: number;
  free(): void;
}

export class Engine {
  readonly version: string;
  compile(source: string): Policy;
}

export function load(factory?: () => Promise<unknown>): Promise<Engine>;
