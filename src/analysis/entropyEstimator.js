const CHARACTER_POOL_SIZES = {
  lowercase: 26,
  uppercase: 26,
  digits: 10,
  symbols: 32,
};

const SUPPORTED_SYMBOLS = "!@#$%^&*()_+-=[]{}:,.?";

function classifyCharacters(password) {
  const pool = new Set();
  if (/[a-z]/.test(password)) pool.add("lowercase");
  if (/[A-Z]/.test(password)) pool.add("uppercase");
  if (/[0-9]/.test(password)) pool.add("digits");
  if ([...password].some((character) => SUPPORTED_SYMBOLS.includes(character))) pool.add("symbols");
  return pool;
}

export function estimateEntropy(password) {
  const value = typeof password === "string" ? password : "";
  const characters = Array.from(value);
  const categories = classifyCharacters(value);
  const observedPoolSize = categories.size > 0
    ? [...categories].reduce((total, category) => total + CHARACTER_POOL_SIZES[category], 0)
    : 0;
  const unsupportedCharacters = new Set(characters.filter((character) => !(/[a-zA-Z0-9]/.test(character) || SUPPORTED_SYMBOLS.includes(character))));
  const poolSize = observedPoolSize + unsupportedCharacters.size || 1;
  const bits = characters.length === 0 ? 0 : characters.length * Math.log2(poolSize);

  return {
    bits: Number(bits.toFixed(1)),
    poolSize,
    unsupportedCharacterCount: unsupportedCharacters.size,
    method: "length multiplied by log2 of the observed character pool",
    assumptions: [
      "Characters are treated as independently and uniformly selected from the observed pool.",
      "This is theoretical entropy, not a crack-time prediction or a complete measure of real-world strength.",
      "Common words, reuse, breaches, human choices, and detected patterns reduce practical strength.",
      "Unsupported Unicode characters are counted only as distinct observed symbols and are not assigned a universal alphabet size.",
    ],
  };
}