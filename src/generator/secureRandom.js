const UINT32_RANGE = 0x100000000;

function getCrypto() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("A cryptographically secure random source is unavailable.");
  }
  return globalThis.crypto;
}

export function secureRandomInt(maxExclusive) {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > UINT32_RANGE) {
    throw new RangeError("maxExclusive must be a positive integer no greater than 2^32.");
  }

  // Reject the incomplete range at the top of uint32 so every result is equally likely.
  const limit = UINT32_RANGE - (UINT32_RANGE % maxExclusive);
  const values = new Uint32Array(1);
  let value;
  do {
    getCrypto().getRandomValues(values);
    value = values[0];
  } while (value >= limit);

  return value % maxExclusive;
}

export function secureChoice(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw new RangeError("Cannot choose from an empty collection.");
  }
  return values[secureRandomInt(values.length)];
}

export function secureShuffle(values) {
  const shuffled = [...values];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomInt(index + 1);
    [shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]];
  }
  return shuffled;
}