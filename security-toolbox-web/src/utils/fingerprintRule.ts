import type { FingerprintRule } from "../api";

/** Mirrors the server's `RULE_ID` regex in FingerprintRuleCatalog. */
const RULE_ID = /^[a-z0-9][a-z0-9._-]{0,79}$/;

export interface RuleProblem {
  field: string;
  message: string;
}

const STRING_LIST_FIELDS = [
  "body",
  "cookies",
  "title",
  "header",
  "faviconHash",
  "faviconMd5",
] as const;

/**
 * Checks that `value` is a non-empty array of non-blank strings. Returns a list of accepted
 * tokens or null when the type is wrong.
 */
function stringListProblems(rule: unknown, field: string): RuleProblem[] | null {
  const problems: RuleProblem[] = [];
  const value = (rule as Record<string, unknown>)?.[field];
  if (value === undefined || value === null) return [];
  let tokens: unknown[];
  if (Array.isArray(value)) {
    tokens = value;
  } else if (typeof value === "string") {
    tokens = [value];
  } else {
    problems.push({ field, message: `${field} 必须是字符串数组` });
    return problems;
  }
  for (const token of tokens) {
    if (typeof token !== "string") {
      problems.push({ field, message: `${field} 中的元素必须是字符串` });
      return problems;
    }
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(token)) {
      problems.push({ field, message: `${field} 不能包含控制字符` });
      return problems;
    }
  }
  return problems;
}

/** Validates a single parsed rule object. Returns a list of field-level problems (empty = valid). */
export function validateFingerprintRuleSyntax(rule: unknown): RuleProblem[] {
  const problems: RuleProblem[] = [];
  if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
    return [{ field: "rule", message: "规则必须是 JSON 对象" }];
  }
  const candidate = rule as FingerprintRule;

  if (typeof candidate.id !== "string" || candidate.id.trim() === "") {
    problems.push({ field: "id", message: "规则标识（id）不能为空" });
  } else if (!RULE_ID.test(candidate.id)) {
    problems.push({
      field: "id",
      message: "规则标识仅允许字母数字和 . _ -，且以小写字母或数字开头（最长 80）",
    });
  }

  if (typeof candidate.name !== "string" || candidate.name.trim() === "") {
    problems.push({ field: "name", message: "规则名称（name）不能为空" });
  }

  if (
    typeof candidate.confidence !== "number" ||
    Number.isNaN(candidate.confidence) ||
    candidate.confidence < 1 ||
    candidate.confidence > 100
  ) {
    problems.push({
      field: "confidence",
      message: "置信度（confidence）必须是 1-100 之间的整数",
    });
  }

  if (candidate.headers !== undefined && candidate.headers !== null) {
    if (
      typeof candidate.headers !== "object" ||
      Array.isArray(candidate.headers)
    ) {
      problems.push({ field: "headers", message: "headers 必须是对象" });
    } else {
      for (const [key, value] of Object.entries(candidate.headers)) {
        if (key.trim() === "") {
          problems.push({ field: "headers", message: "headers 键名不能为空" });
          break;
        }
        const list = Array.isArray(value) ? value : [value];
        for (const token of list) {
          if (typeof token !== "string") {
            problems.push({
              field: "headers",
              message: `headers.${key} 的元素必须是字符串`,
            });
            return problems;
          }
        }
      }
    }
  }

  for (const field of STRING_LIST_FIELDS) {
    const fieldProblems = stringListProblems(
      candidate as unknown as Record<string, unknown>,
      field,
    );
    if (fieldProblems) problems.push(...fieldProblems);
  }

  return problems;
}

/** Parses a JSON editor string into a rule object. Throws with a message on invalid JSON. */
export function parseFingerprintRuleJson(text: string): FingerprintRule {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("规则内容不能为空");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (error) {
    throw new Error(`JSON 语法错误：${errorMessageDetail(error)}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("规则根节点必须是 JSON 对象");
  }
  return parsed as FingerprintRule;
}

function errorMessageDetail(error: unknown): string {
  if (error instanceof Error) {
    return error.message.replace(/^Unexpected token /, "").slice(0, 120);
  }
  return "无法解析";
}

/** Normalizes a parsed rule to a canonical object for display in the editor. */
export function normalizeFingerprintRuleForEditor(
  rule: FingerprintRule,
): FingerprintRule {
  return {
    id: rule.id,
    name: rule.name,
    category: rule.category ?? "",
    confidence: rule.confidence,
    headers: rule.headers ?? {},
    body: rule.body ?? [],
    cookies: rule.cookies ?? [],
    title: rule.title ?? [],
    header: rule.header ?? [],
    faviconHash: rule.faviconHash ?? [],
    faviconMd5: rule.faviconMd5 ?? [],
  };
}