import { COMMON_WORDS, normalizeForLookup } from "./commonPasswords.js";

const KEYBOARD_SEQUENCES = ["qwerty", "asdfgh", "zxcvbn", "12345", "09876", "!@#$%"];
const PREDICTABLE_PREFIXES = ["password", "admin", "welcome", "letmein", "qwerty", "user"];

function pattern(type, risk, explanation, recommendation) {
  return { type, risk, explanation, recommendation };
}

function hasSequentialRun(value) {
  const characters = Array.from(value.toLowerCase());
  for (let index = 0; index <= characters.length - 3; index += 1) {
    const first = characters[index].charCodeAt(0);
    const second = characters[index + 1].charCodeAt(0);
    const third = characters[index + 2].charCodeAt(0);
    if (second - first === 1 && third - second === 1) return true;
    if (second - first === -1 && third - second === -1) return true;
  }
  return false;
}

function hasRepeatedSubstring(value) {
  for (let size = 2; size <= Math.floor(value.length / 2); size += 1) {
    for (let index = 0; index + size * 2 <= value.length; index += 1) {
      const part = value.slice(index, index + size);
      if (value.slice(index + size, index + size * 2) === part) return true;
    }
  }
  return false;
}

function hasObviousSubstitution(value) {
  const normalized = normalizeForLookup(value);
  const translated = normalized
    .replaceAll("@", "a")
    .replaceAll("0", "o")
    .replaceAll("1", "i")
    .replaceAll("3", "e")
    .replaceAll("4", "a")
    .replaceAll("5", "s")
    .replaceAll("$", "s")
    .replaceAll("7", "t");
  return translated !== normalized && [...COMMON_WORDS].some((word) => translated.includes(word));
}

export function detectPatterns(password) {
  const value = typeof password === "string" ? password : "";
  if (!value) return [];
  const lower = normalizeForLookup(value);
  const substitutionNormalized = lower
    .replaceAll("@", "a")
    .replaceAll("0", "o")
    .replaceAll("1", "i")
    .replaceAll("3", "e")
    .replaceAll("4", "a")
    .replaceAll("5", "s")
    .replaceAll("$", "s")
    .replaceAll("7", "t");
  const findings = [];

  if (/(.)\1{2,}/u.test(value)) {
    findings.push(pattern("repeated characters", "high", "A character is repeated several times in a row, which reduces the search space.", "Avoid runs of the same character."));
  }
  if (hasRepeatedSubstring(value)) {
    findings.push(pattern("repeated substring", "high", "A multi-character sequence appears repeatedly, making the value easier to predict.", "Use unrelated characters or words instead of repeating a block."));
  }
  if (hasSequentialRun(value)) {
    findings.push(pattern("sequential characters", "medium", "Ascending or descending character runs are common guesses.", "Replace sequences such as abc, 123, or their reverse."));
  }
  if (KEYBOARD_SEQUENCES.some((sequence) => lower.includes(sequence) || lower.includes([...sequence].reverse().join("")))) {
    findings.push(pattern("keyboard-style sequence", "medium", "A keyboard row or familiar key sequence is frequently guessed.", "Avoid adjacent-key patterns and keyboard walks."));
  }
  if (/\d{2,4}$/.test(value)) {
    findings.push(pattern("predictable numeric suffix", "medium", "A short number suffix is a common password modification.", "Do not append a simple number sequence."));
  }
  if (/^(19|20)\d{2}$/.test(value) || /(?:19|20)\d{2}/.test(value)) {
    findings.push(pattern("year", "medium", "A four-digit year is a predictable personal or temporal pattern.", "Avoid years and other personally meaningful dates."));
  }
  if (PREDICTABLE_PREFIXES.some((prefix) => lower.startsWith(prefix) || substitutionNormalized.startsWith(prefix))) {
    findings.push(pattern("predictable prefix", "high", "The value begins with a frequently guessed password word.", "Do not start with common words such as password, admin, or welcome."));
  }
  if (hasObviousSubstitution(value)) {
    findings.push(pattern("obvious substitution", "medium", "Symbol or digit substitutions preserve a recognizable dictionary word.", "Do not rely on substitutions such as @ for a or 0 for o."));
  }
  const numericSuffix = value.match(/\d+$/)?.[0];
  if (numericSuffix) {
    const rawPrefix = value.slice(0, -numericSuffix.length);
    const canonicalPrefix = normalizeForLookup(rawPrefix)
      .replaceAll("@", "a")
      .replaceAll("0", "o")
      .replaceAll("1", "i")
      .replaceAll("3", "e")
      .replaceAll("4", "a")
      .replaceAll("5", "s")
      .replaceAll("$", "s")
      .replaceAll("7", "t");
    if (/^[a-z]+$/.test(canonicalPrefix) && COMMON_WORDS.has(canonicalPrefix)) {
    findings.push(pattern("dictionary word plus number", "high", "A common word followed by digits is a standard password guess.", "Use unrelated random words or characters instead."));
    }
  }

  return findings;
}