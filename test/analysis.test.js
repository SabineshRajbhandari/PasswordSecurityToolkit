import assert from "node:assert/strict";
import { test } from "node:test";
import { isCommonPassword, normalizeForLookup } from "../src/analysis/commonPasswords.js";
import { estimateEntropy } from "../src/analysis/entropyEstimator.js";
import { detectPatterns } from "../src/analysis/patternDetector.js";
import { analyzePassword } from "../src/analysis/passwordAnalyzer.js";

test("analysis handles an empty and very short password", () => {
  const result = analyzePassword("abc");
  assert.equal(result.length.rating, "very-short");
  assert.equal(result.strength, "Very weak");
  assert.ok(result.warnings.some((warning) => warning.includes("12 characters")));
  assert.ok(result.patterns.some((finding) => finding.type === "sequential characters"));
});

test("common-password detection normalizes lookup without returning the password", () => {
  assert.equal(normalizeForLookup("  PASSWORD  "), "password");
  assert.equal(isCommonPassword("  PASSWORD  "), true);
  const result = analyzePassword("password");
  assert.equal(result.commonPassword.detected, true);
  assert.equal(Object.prototype.hasOwnProperty.call(result, "password"), false);
});

test("pattern detection identifies repeated and sequential patterns", () => {
  const repeated = detectPatterns("aaaa1111");
  assert.ok(repeated.some((finding) => finding.type === "repeated characters"));
  assert.ok(repeated.some((finding) => finding.type === "repeated substring"));

  const sequential = detectPatterns("abc123");
  assert.ok(sequential.some((finding) => finding.type === "sequential characters"));
  assert.ok(sequential.some((finding) => finding.type === "predictable numeric suffix"));
});

test("pattern detection identifies prefixes, years, substitutions, and word-number patterns", () => {
  const result = analyzePassword("P@ssword2024");
  const types = result.patterns.map((finding) => finding.type);
  assert.ok(types.includes("predictable prefix"));
  assert.ok(types.includes("year"));
  assert.ok(types.includes("obvious substitution"));
  assert.ok(types.includes("dictionary word plus number"));
});

test("entropy reports theoretical assumptions and increases with character pool", () => {
  const short = estimateEntropy("abc");
  const mixed = estimateEntropy("aB7!");
  assert.equal(short.bits, 14.1);
  assert.equal(mixed.bits, 26.2);
  assert.ok(mixed.bits > short.bits);
  assert.match(mixed.assumptions[0], /independently and uniformly/);
  assert.match(mixed.assumptions[1], /theoretical entropy/);
});

test("long mixed-character passwords receive a stronger multidimensional assessment", () => {
  const result = analyzePassword("aZ7!mQ2#vL9@xR4$");
  assert.equal(result.length.rating, "long");
  assert.equal(result.characterSets.characterSetCount, 4);
  assert.equal(result.commonPassword.detected, false);
  assert.equal(result.patterns.length, 0);
  assert.ok(result.entropy.bits > 80);
  assert.ok(result.score >= 85);
  assert.equal(result.strength, "Very strong");
});

test("ordinary mixed text does not trigger every pattern detector", () => {
  const result = analyzePassword("MapleCandleOrbit");
  assert.equal(result.commonPassword.detected, false);
  assert.equal(result.patterns.some((finding) => finding.type === "sequential characters"), false);
  assert.equal(result.patterns.some((finding) => finding.type === "repeated characters"), false);
});

test("analysis handles long input without exposing it in the result", () => {
  const value = "A".repeat(256);
  const result = analyzePassword(value);
  assert.equal(result.length.value, 256);
  assert.ok(result.warnings.length > 0);
  assert.equal(JSON.stringify(result).includes(value), false);
});