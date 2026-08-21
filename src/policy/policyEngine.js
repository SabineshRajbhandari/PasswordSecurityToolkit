import { isCommonPassword } from "../analysis/commonPasswords.js";
import { analyzePassword } from "../analysis/passwordAnalyzer.js";

export const DEFAULT_POLICY = {
  minimumLength: 12,
  maximumLength: 128,
  requireLowercase: true,
  requireUppercase: true,
  requireDigit: true,
  requireSymbol: true,
  minimumCharacterSetDiversity: 3,
  rejectCommonPasswords: true,
  rejectRepeatedCharacters: false,
  rejectSequentialCharacters: false,
  rejectPredictablePatterns: false,
  rejectBreachedPasswords: false,
};

export const POLICY_PRESETS = {
  DEFAULT: { ...DEFAULT_POLICY },
  STRONG: {
    ...DEFAULT_POLICY,
    minimumLength: 16,
    maximumLength: 128,
    minimumCharacterSetDiversity: 4,
    rejectRepeatedCharacters: true,
    rejectSequentialCharacters: true,
    rejectPredictablePatterns: true,
    rejectBreachedPasswords: true,
  },
  CUSTOM: { ...DEFAULT_POLICY },
};

function normalizeBreachStatus(breachResult) {
  if (!breachResult) return "not_checked";
  if (breachResult.status === "found") return "found";
  if (breachResult.status === "not_found") return "not_found";
  if (breachResult.status === "error" || breachResult.status === "unavailable") return "unavailable";
  if (breachResult.status === "checking") return "not_checked";
  return "not_checked";
}

function addUnique(items, value) {
  if (!items.includes(value)) items.push(value);
}

export function validatePolicy(policy = DEFAULT_POLICY) {
  const normalized = { ...DEFAULT_POLICY, ...policy };

  if (!Number.isInteger(normalized.minimumLength) || normalized.minimumLength < 0) {
    throw new RangeError("Policy minimum length must be a non-negative integer.");
  }
  if (!Number.isInteger(normalized.maximumLength) || normalized.maximumLength < normalized.minimumLength) {
    throw new RangeError("Policy maximum length must be an integer greater than or equal to the minimum length.");
  }

  for (const field of [
    "requireLowercase",
    "requireUppercase",
    "requireDigit",
    "requireSymbol",
    "rejectCommonPasswords",
    "rejectRepeatedCharacters",
    "rejectSequentialCharacters",
    "rejectPredictablePatterns",
    "rejectBreachedPasswords",
  ]) {
    if (typeof normalized[field] !== "boolean") {
      throw new TypeError(`Policy field ${field} must be a boolean.`);
    }
  }

  if (!Number.isInteger(normalized.minimumCharacterSetDiversity)
    || normalized.minimumCharacterSetDiversity < 0
    || normalized.minimumCharacterSetDiversity > 4) {
    throw new RangeError("Policy minimum character set diversity must be an integer between 0 and 4.");
  }

  return normalized;
}

function evaluateLengthRules(policy, password, result) {
  const length = Array.from(password).length;
  if (policy.minimumLength > 0) {
    if (length < policy.minimumLength) {
      addUnique(result.failedRules, `Password length must be at least ${policy.minimumLength} characters.`);
      addUnique(result.recommendations, `Increase the password length to at least ${policy.minimumLength} characters.`);
    } else {
      addUnique(result.passedRules, `Minimum length satisfied (${length}/${policy.minimumLength}).`);
    }
  }

  if (policy.maximumLength > 0) {
    if (length > policy.maximumLength) {
      addUnique(result.failedRules, `Password length must be at most ${policy.maximumLength} characters.`);
      addUnique(result.recommendations, `Reduce the password to at most ${policy.maximumLength} characters.`);
    } else {
      addUnique(result.passedRules, `Maximum length satisfied (${length}/${policy.maximumLength}).`);
    }
  }
}

function evaluateCharacterRules(policy, password, result) {
  const hasLowercase = /[a-z]/u.test(password);
  const hasUppercase = /[A-Z]/u.test(password);
  const hasDigit = /\d/u.test(password);
  const hasSymbol = /[^\p{L}\p{N}]/u.test(password);
  const characterSetCount = [hasLowercase, hasUppercase, hasDigit, hasSymbol].filter(Boolean).length;

  const rules = [
    {
      enabled: policy.requireLowercase,
      present: hasLowercase,
      label: "lowercase",
      message: "Contains at least one lowercase character.",
      failure: "Password must contain at least one lowercase character.",
      recommendation: "Add at least one lowercase character.",
    },
    {
      enabled: policy.requireUppercase,
      present: hasUppercase,
      label: "uppercase",
      message: "Contains at least one uppercase character.",
      failure: "Password must contain at least one uppercase character.",
      recommendation: "Add at least one uppercase character.",
    },
    {
      enabled: policy.requireDigit,
      present: hasDigit,
      label: "digit",
      message: "Contains at least one digit.",
      failure: "Password must contain at least one digit.",
      recommendation: "Add at least one digit.",
    },
    {
      enabled: policy.requireSymbol,
      present: hasSymbol,
      label: "symbol",
      message: "Contains at least one symbol.",
      failure: "Password must contain at least one symbol.",
      recommendation: "Add at least one symbol.",
    },
  ];

  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.present) {
      addUnique(result.passedRules, rule.message);
    } else {
      addUnique(result.failedRules, rule.failure);
      addUnique(result.recommendations, rule.recommendation);
    }
  }

  if (policy.minimumCharacterSetDiversity > 0) {
    if (characterSetCount >= policy.minimumCharacterSetDiversity) {
      addUnique(result.passedRules, `Character-set diversity requirement satisfied (${characterSetCount}/${policy.minimumCharacterSetDiversity}).`);
    } else {
      addUnique(result.failedRules, `Password does not meet the minimum character-set diversity of ${policy.minimumCharacterSetDiversity}.`);
      addUnique(result.recommendations, `Use characters from at least ${policy.minimumCharacterSetDiversity} different categories.`);
    }
  }
}

function evaluatePatternRules(policy, password, result) {
  const analysis = analyzePassword(password);
  const patternLookup = new Set(analysis.patterns.map((finding) => finding.type));

  if (policy.rejectCommonPasswords && isCommonPassword(password)) {
    addUnique(result.failedRules, "Password matches a common password and is not allowed by policy.");
    addUnique(result.recommendations, "Choose a unique password that is not commonly used or reused.");
  }

  if (policy.rejectRepeatedCharacters && (patternLookup.has("repeated characters") || patternLookup.has("repeated substring"))) {
    addUnique(result.failedRules, "Password contains repeated characters or repeated substrings, which are not allowed by policy.");
    addUnique(result.recommendations, "Remove repeated characters or repeated substrings from the password.");
  }

  if (policy.rejectSequentialCharacters && (patternLookup.has("sequential characters") || patternLookup.has("keyboard-style sequence"))) {
    addUnique(result.failedRules, "Password contains a sequential or keyboard-style pattern that is not allowed by policy.");
    addUnique(result.recommendations, "Avoid sequential or keyboard-style runs such as abc, 123, or qwerty.");
  }

  if (policy.rejectPredictablePatterns && (
    patternLookup.has("repeated characters")
    || patternLookup.has("repeated substring")
    || patternLookup.has("sequential characters")
    || patternLookup.has("keyboard-style sequence")
    || patternLookup.has("predictable numeric suffix")
    || patternLookup.has("year")
    || patternLookup.has("predictable prefix")
    || patternLookup.has("obvious substitution")
    || patternLookup.has("dictionary word plus number")
  )) {
    addUnique(result.failedRules, "Password uses a predictable pattern that is not allowed by policy.");
    addUnique(result.recommendations, "Avoid repeated, sequential, predictable prefixes, years, word-plus-number patterns, and obvious substitutions.");
  }
}

function evaluateBreachRules(policy, breachResult, result) {
  const status = normalizeBreachStatus(breachResult);
  result.breachStatus = status;

  if (status === "found") {
    if (policy.rejectBreachedPasswords) {
      addUnique(result.failedRules, "Password was found in known breach data and is not allowed by policy.");
      addUnique(result.recommendations, "Use a different password that does not appear in breach intelligence.");
    }
  } else if (status === "not_found") {
    addUnique(result.passedRules, "Password was not found in the breach dataset.");
  } else if (status === "unavailable") {
    addUnique(result.warnings, "The breach check was unavailable, so the password was not automatically classified as safe.");
  } else if (status === "not_checked") {
    if (policy.rejectBreachedPasswords) {
      addUnique(result.warnings, "No breach check was performed, so breach status remains not checked.");
    }
  }
}

export function evaluatePasswordPolicy(password, policy = DEFAULT_POLICY, breachResult = null) {
  const normalized = validatePolicy(policy);
  const value = typeof password === "string" ? password : "";
  const result = {
    compliant: true,
    passedRules: [],
    failedRules: [],
    warnings: [],
    recommendations: [],
    breachStatus: normalizeBreachStatus(breachResult),
  };

  evaluateLengthRules(normalized, value, result);
  evaluateCharacterRules(normalized, value, result);
  evaluatePatternRules(normalized, value, result);
  evaluateBreachRules(normalized, breachResult, result);

  if (result.failedRules.length > 0) {
    result.compliant = false;
  }

  result.warnings = [...new Set(result.warnings)];
  result.recommendations = [...new Set(result.recommendations)];
  result.passedRules = [...new Set(result.passedRules)];
  result.failedRules = [...new Set(result.failedRules)];

  return result;
}
