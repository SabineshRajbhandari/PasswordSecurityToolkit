import {
  AMBIGUOUS_CHARACTERS,
  CHARACTER_SETS,
  DEFAULT_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from "./characterSets.js";
import { secureChoice, secureShuffle } from "./secureRandom.js";

export const DEFAULT_PASSWORD_OPTIONS = {
  length: DEFAULT_PASSWORD_LENGTH,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

export function validatePasswordOptions(options = {}) {
  const normalized = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  if (!Number.isInteger(normalized.length) || normalized.length < MIN_PASSWORD_LENGTH || normalized.length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(`Password length must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH}.`);
  }

  const enabledTypes = ["lowercase", "uppercase", "digits", "symbols"].filter((type) => normalized[type]);
  if (enabledTypes.length === 0) {
    throw new Error("At least one character type must be selected.");
  }
  if (normalized.length < enabledTypes.length) {
    throw new RangeError("Password length is too short for the selected character types.");
  }
  if (typeof normalized.excludeAmbiguous !== "boolean" || enabledTypes.some((type) => typeof normalized[type] !== "boolean")) {
    throw new TypeError("Password options must use boolean character-type settings.");
  }

  return { ...normalized, enabledTypes };
}

function getCharacterSet(type, excludeAmbiguous) {
  const characters = [...CHARACTER_SETS[type]];
  return excludeAmbiguous
    ? characters.filter((character) => !AMBIGUOUS_CHARACTERS.has(character))
    : characters;
}

export function generatePassword(options = {}) {
  const normalized = validatePasswordOptions(options);
  const sets = normalized.enabledTypes.map((type) => getCharacterSet(type, normalized.excludeAmbiguous));
  const pool = sets.flat();
  if (pool.length === 0) {
    throw new Error("The selected options produce an empty character set.");
  }

  const password = sets.map((set) => secureChoice(set));
  while (password.length < normalized.length) {
    password.push(secureChoice(pool));
  }

  return secureShuffle(password).join("");
}