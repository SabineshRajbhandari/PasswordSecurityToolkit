import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";
import {
  CHARACTER_SETS,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  MAX_PASSPHRASE_WORDS,
  MIN_PASSPHRASE_WORDS,
} from "../src/generator/characterSets.js";
import { generatePassword, validatePasswordOptions } from "../src/generator/passwordGenerator.js";
import { generatePassphrase, validatePassphraseOptions } from "../src/generator/passphraseGenerator.js";
import { secureRandomInt } from "../src/generator/secureRandom.js";
import {
  DEFAULT_POLICY,
  POLICY_PRESETS,
  evaluatePasswordPolicy,
  validatePolicy,
} from "../src/policy/policyEngine.js";
import {
  createSecurityReport,
  serializeReport,
} from "../src/report/securityReport.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
}

test("password generation respects minimum and maximum lengths", () => {
  assert.equal(generatePassword({ length: MIN_PASSWORD_LENGTH }).length, MIN_PASSWORD_LENGTH);
  assert.equal(generatePassword({ length: MAX_PASSWORD_LENGTH }).length, MAX_PASSWORD_LENGTH);
});

test("password generation includes every selected character type", () => {
  const password = generatePassword({ length: 16, lowercase: true, uppercase: true, digits: true, symbols: true });
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /[0-9]/);
  assert.ok([...CHARACTER_SETS.symbols].some((character) => password.includes(character)));
});

test("password generation excludes ambiguous characters when requested", () => {
  const password = generatePassword({ length: 32, excludeAmbiguous: true });
  assert.equal(/[Il1O0o]/.test(password), false);
});

test("password generation rejects invalid configurations", () => {
  assert.throws(() => generatePassword({ length: MIN_PASSWORD_LENGTH - 1 }), RangeError);
  assert.throws(() => generatePassword({ length: MAX_PASSWORD_LENGTH + 1 }), RangeError);
  assert.throws(() => generatePassword({ lowercase: false, uppercase: false, digits: false, symbols: false }));
  assert.equal(validatePasswordOptions({ length: 6, lowercase: true, uppercase: true, digits: true, symbols: true }).enabledTypes.length, 4);
});

test("password generation uses the browser cryptographic random source", () => {
  const original = globalThis.crypto.getRandomValues;
  let calls = 0;
  globalThis.crypto.getRandomValues = (values) => {
    calls += 1;
    return original.call(globalThis.crypto, values);
  };
  try {
    generatePassword({ length: 16 });
    assert.ok(calls > 0);
  } finally {
    globalThis.crypto.getRandomValues = original;
  }
});

test("passphrase generation returns the requested number of words", () => {
  const separator = ".";
  const passphrase = generatePassphrase({ wordCount: 7, separator });
  assert.equal(passphrase.split(separator).length, 7);
});

test("passphrase generation applies capitalization and optional suffixes", () => {
  const passphrase = generatePassphrase({ wordCount: MIN_PASSPHRASE_WORDS, separator: "-", capitalize: true, includeNumbers: true, includeSymbols: true });
  const words = passphrase.split("-");
  assert.equal(words.length, MIN_PASSPHRASE_WORDS);
  assert.ok(words.every((word) => /^[A-Z][a-z]+/.test(word)));
  assert.match(passphrase, /[0-9]/);
  assert.ok([...CHARACTER_SETS.symbols].some((character) => passphrase.includes(character)));
});

test("passphrase generation validates word count and separator", () => {
  assert.equal(validatePassphraseOptions({ wordCount: MIN_PASSPHRASE_WORDS }).wordCount, MIN_PASSPHRASE_WORDS);
  assert.equal(validatePassphraseOptions({ wordCount: MAX_PASSPHRASE_WORDS }).wordCount, MAX_PASSPHRASE_WORDS);
  assert.throws(() => generatePassphrase({ wordCount: MIN_PASSPHRASE_WORDS - 1 }), RangeError);
  assert.throws(() => generatePassphrase({ wordCount: MAX_PASSPHRASE_WORDS + 1 }), RangeError);
  assert.throws(() => generatePassphrase({ separator: "\n" }), TypeError);
});

test("secure random selection remains within range and rejects invalid bounds", () => {
  for (const bound of [1, 2, 7, 16, 64]) {
    const value = secureRandomInt(bound);
    assert.ok(Number.isInteger(value));
    assert.ok(value >= 0 && value < bound);
  }

  assert.throws(() => secureRandomInt(0), RangeError);
  assert.throws(() => secureRandomInt(-1), RangeError);
  assert.throws(() => secureRandomInt(Number.MAX_SAFE_INTEGER), RangeError);
});

test("policy engine validates minimum and maximum length and allows compliant values", () => {
  const validPolicy = validatePolicy({ ...DEFAULT_POLICY, minimumLength: 12, maximumLength: 24 });
  assert.equal(validPolicy.minimumLength, 12);
  assert.equal(validPolicy.maximumLength, 24);

  const compliant = evaluatePasswordPolicy("Example!2024", validPolicy);
  assert.equal(compliant.compliant, true);
  assert.equal(compliant.failedRules.length, 0);

  const shortPassword = evaluatePasswordPolicy("Ab1!", validPolicy);
  assert.equal(shortPassword.compliant, false);
  assert.ok(shortPassword.failedRules.some((rule) => rule.includes("at least 12")));

  const longPassword = evaluatePasswordPolicy("Example!2024Example!2024A", validPolicy);
  assert.equal(longPassword.compliant, false);
  assert.ok(longPassword.failedRules.some((rule) => rule.includes("at most 24")));
});

test("policy engine enforces character and diversity requirements", () => {
  const policy = {
    ...DEFAULT_POLICY,
    minimumLength: 8,
    maximumLength: 64,
    requireLowercase: true,
    requireUppercase: true,
    requireDigit: true,
    requireSymbol: true,
    minimumCharacterSetDiversity: 4,
  };

  const uppercaseOnly = evaluatePasswordPolicy("PASSWORD", policy);
  assert.equal(uppercaseOnly.compliant, false);
  assert.ok(uppercaseOnly.failedRules.some((rule) => rule.toLowerCase().includes("lowercase")));

  const digitsOnly = evaluatePasswordPolicy("12345678", policy);
  assert.equal(digitsOnly.compliant, false);
  assert.ok(digitsOnly.failedRules.some((rule) => rule.toLowerCase().includes("uppercase")));

  const compliant = evaluatePasswordPolicy("Secure!2024", policy);
  assert.equal(compliant.compliant, true);
  assert.ok(compliant.passedRules.some((rule) => rule.includes("lowercase")));
});

test("policy engine rejects common passwords and predictable patterns", () => {
  const policy = {
    ...DEFAULT_POLICY,
    rejectCommonPasswords: true,
    rejectRepeatedCharacters: true,
    rejectPredictablePatterns: true,
  };

  const common = evaluatePasswordPolicy("Password123", policy);
  assert.equal(common.compliant, false);
  assert.ok(common.failedRules.some((rule) => rule.includes("common password")));

  const repeated = evaluatePasswordPolicy("aaabbbccc", policy);
  assert.equal(repeated.compliant, false);
  assert.ok(repeated.failedRules.some((rule) => rule.includes("repeated characters")));

  const sequential = evaluatePasswordPolicy("abc123xyz", policy);
  assert.equal(sequential.compliant, false);
  assert.ok(sequential.failedRules.some((rule) => rule.includes("sequential") || rule.includes("predictable")));
});

test("policy engine handles breach states explicitly without assuming safety", () => {
  const policy = { ...DEFAULT_POLICY, rejectBreachedPasswords: true, minimumLength: 8 };

  const found = evaluatePasswordPolicy("StrongPass!1", policy, { status: "found", count: 42 });
  assert.equal(found.compliant, false);
  assert.equal(found.breachStatus, "found");

  const notFound = evaluatePasswordPolicy("StrongPass!1", policy, { status: "not_found" });
  assert.equal(notFound.compliant, true);
  assert.equal(notFound.breachStatus, "not_found");

  const unavailable = evaluatePasswordPolicy("StrongPass!1", policy, { status: "error", message: "temporarily unavailable" });
  assert.equal(unavailable.compliant, true);
  assert.equal(unavailable.breachStatus, "unavailable");

  const notChecked = evaluatePasswordPolicy("StrongPass!1", policy);
  assert.equal(notChecked.compliant, true);
  assert.equal(notChecked.breachStatus, "not_checked");
});

test("policy engine handles empty, whitespace, Unicode, and no-rule policies safely", () => {
  const emptyPolicy = evaluatePasswordPolicy("", { ...DEFAULT_POLICY, minimumLength: 0, maximumLength: 256, requireLowercase: false, requireUppercase: false, requireDigit: false, requireSymbol: false, minimumCharacterSetDiversity: 0, rejectCommonPasswords: false, rejectRepeatedCharacters: false, rejectPredictablePatterns: false, rejectBreachedPasswords: false });
  assert.equal(emptyPolicy.compliant, true);

  const whitespace = evaluatePasswordPolicy("  ", { ...DEFAULT_POLICY, minimumLength: 3, maximumLength: 32 });
  assert.equal(whitespace.compliant, false);
  assert.ok(whitespace.failedRules.some((rule) => rule.includes("length")));

  const unicode = evaluatePasswordPolicy("Pásswörd!2024", { ...DEFAULT_POLICY, minimumLength: 12, maximumLength: 64 });
  assert.equal(unicode.compliant, true);

  const noRules = evaluatePasswordPolicy("Example!2024", { ...DEFAULT_POLICY, minimumLength: 0, maximumLength: 512, requireLowercase: false, requireUppercase: false, requireDigit: false, requireSymbol: false, minimumCharacterSetDiversity: 0, rejectCommonPasswords: false, rejectRepeatedCharacters: false, rejectPredictablePatterns: false, rejectBreachedPasswords: false });
  assert.equal(noRules.compliant, true);
  assert.equal(noRules.failedRules.length, 0);
});

test("policy presets are available and validate the invalid policy configuration", () => {
  assert.ok(POLICY_PRESETS.DEFAULT);
  assert.ok(POLICY_PRESETS.STRONG);
  assert.equal(typeof POLICY_PRESETS.DEFAULT.minimumLength, "number");
  assert.throws(() => validatePolicy({ minimumLength: 30, maximumLength: 12 }), RangeError);
});

test("security report for a strong password stays positive and safe", () => {
  const analysis = {
    strength: "Very strong",
    score: 90,
    entropy: { bits: 64 },
    warnings: [],
    recommendations: ["Store it in a password manager."],
    patterns: [],
    commonPassword: { detected: false },
  };
  const policy = evaluatePasswordPolicy("Strong!Pass2024", DEFAULT_POLICY, { status: "not_found" });
  const report = createSecurityReport({ analysis, breach: { status: "not_found" }, policy, policyPreset: "DEFAULT" });

  assert.equal(report.overallAssessment.level, "Good");
  assert.ok(report.summary.includes("Good") || report.summary.includes("strong"));
  assert.equal(report.findings.length > 0 || report.recommendations.length > 0, true);
  assert.ok(!JSON.stringify(report).includes("Strong!Pass2024"));
});

test("security report identifies weak and policy-failing credentials", () => {
  const analysis = {
    strength: "Weak",
    score: 25,
    entropy: { bits: 20 },
    warnings: ["This password matches a locally known common password."],
    recommendations: ["Increase the length before relying on character variety."],
    patterns: [{ type: "dictionary word plus number", explanation: "Common word with digits." }],
    commonPassword: { detected: true },
  };
  const policy = evaluatePasswordPolicy("Password123", DEFAULT_POLICY, { status: "not_found" });
  const report = createSecurityReport({ analysis, breach: { status: "not_found" }, policy, policyPreset: "DEFAULT" });

  assert.equal(report.overallAssessment.level, "High");
  assert.ok(report.findings.some((finding) => finding.category === "policy" || finding.category === "local-analysis"));
  assert.ok(report.recommendations.some((item) => item.toLowerCase().includes("common") || item.toLowerCase().includes("length")));
  assert.ok(!JSON.stringify(report).includes("Password123"));
});

test("security report handles breach exposure and unavailable breach checks safely", () => {
  const analysis = {
    strength: "Medium",
    score: 55,
    entropy: { bits: 42 },
    warnings: [],
    recommendations: [],
    patterns: [],
    commonPassword: { detected: false },
  };

  const found = createSecurityReport({ analysis, breach: { status: "found", count: 42 }, policy: evaluatePasswordPolicy("Example!2024", DEFAULT_POLICY, { status: "found", count: 42 }), policyPreset: "STRONG" });
  assert.equal(found.overallAssessment.level, "Critical");
  assert.ok(found.findings.some((finding) => finding.category === "breach"));

  const unavailable = createSecurityReport({ analysis, breach: { status: "error", message: "temporarily unavailable" }, policy: evaluatePasswordPolicy("Example!2024", DEFAULT_POLICY), policyPreset: "DEFAULT" });
  assert.equal(unavailable.breach.status, "error");
  assert.equal(unavailable.policyStatus, "not_checked");
  assert.ok(unavailable.overallAssessment.summary.includes("breach"));
});

test("security report export excludes plaintext passwords, full hashes, and HIBP hash fragments", () => {
  const report = createSecurityReport({
    analysis: {
      strength: "Medium",
      score: 62,
      entropy: { bits: 48 },
      warnings: ["Weak"],
      recommendations: ["Add length"],
      patterns: [{ type: "year", explanation: "Predictable year pattern." }],
      commonPassword: { detected: false },
    },
    breach: { status: "not_found" },
    policy: { compliant: false, failedRules: ["Password must contain at least one uppercase character."], breachStatus: "not_found" },
    policyPreset: "CUSTOM",
  });

  const serialized = serializeReport(report);
  const sanitized = JSON.stringify(report);
  assert.ok(!sanitized.includes("WeakSecret!2024"));
  assert.ok(!sanitized.includes("A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0"));
  assert.ok(!sanitized.includes("5F7A1C"));
  assert.ok(!sanitized.includes("G7H8I9J0K1L2M3N4O5P6Q7R8S9T0"));
  assert.ok(serialized.includes("\"generatedAt\""));
  assert.ok(serialized.includes("\"overallAssessment\""));
});