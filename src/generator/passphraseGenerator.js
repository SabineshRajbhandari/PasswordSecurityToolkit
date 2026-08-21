import {
  DEFAULT_PASSPHRASE_WORDS,
  MAX_PASSPHRASE_WORDS,
  MIN_PASSPHRASE_WORDS,
  PASSPHRASE_WORDS,
  CHARACTER_SETS,
} from "./characterSets.js";
import { secureChoice } from "./secureRandom.js";

export const DEFAULT_PASSPHRASE_OPTIONS = {
  wordCount: DEFAULT_PASSPHRASE_WORDS,
  separator: "-",
  capitalize: false,
  includeNumbers: false,
  includeSymbols: false,
};

export function validatePassphraseOptions(options = {}) {
  const normalized = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  if (!Number.isInteger(normalized.wordCount) || normalized.wordCount < MIN_PASSPHRASE_WORDS || normalized.wordCount > MAX_PASSPHRASE_WORDS) {
    throw new RangeError(`Word count must be between ${MIN_PASSPHRASE_WORDS} and ${MAX_PASSPHRASE_WORDS}.`);
  }
  if (typeof normalized.separator !== "string" || normalized.separator.length > 8 || /[\r\n]/.test(normalized.separator)) {
    throw new TypeError("Separator must be a short single-line string.");
  }
  for (const option of ["capitalize", "includeNumbers", "includeSymbols"]) {
    if (typeof normalized[option] !== "boolean") {
      throw new TypeError(`Passphrase option ${option} must be boolean.`);
    }
  }
  return normalized;
}

export function generatePassphrase(options = {}) {
  const normalized = validatePassphraseOptions(options);
  const words = Array.from({ length: normalized.wordCount }, () => {
    const word = secureChoice(PASSPHRASE_WORDS);
    return normalized.capitalize ? word[0].toUpperCase() + word.slice(1) : word;
  });
  let passphrase = words.join(normalized.separator);
  if (normalized.includeNumbers) passphrase += secureChoice([...CHARACTER_SETS.digits]);
  if (normalized.includeSymbols) passphrase += secureChoice([...CHARACTER_SETS.symbols]);
  return passphrase;
}