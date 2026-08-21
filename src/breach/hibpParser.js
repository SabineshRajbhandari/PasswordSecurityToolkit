const SUFFIX_LENGTH = 35;
const SUFFIX_PATTERN = /^[A-F0-9]{35}$/;

export function parseHibpResponse(responseText) {
  if (typeof responseText !== "string") {
    throw new Error("The breach-check service returned an invalid response.");
  }
  if (responseText.trim() === "") return [];

  const entries = [];
  for (const line of responseText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const separatorIndex = trimmed.indexOf(":");
    if (separatorIndex <= 0 || separatorIndex === trimmed.length - 1) {
      throw new Error("The breach-check service returned an invalid response.");
    }

    const suffix = trimmed.slice(0, separatorIndex).toUpperCase();
    const countText = trimmed.slice(separatorIndex + 1).trim();
    const count = Number(countText);
    if (suffix.length !== SUFFIX_LENGTH || !SUFFIX_PATTERN.test(suffix) || !Number.isSafeInteger(count) || count < 0) {
      throw new Error("The breach-check service returned an invalid response.");
    }
    entries.push({ suffix, count });
  }

  return entries;
}

export function findBreachMatch(entries, suffix) {
  if (!Array.isArray(entries) || typeof suffix !== "string") {
    throw new TypeError("A parsed response and hash suffix are required.");
  }
  const normalizedSuffix = suffix.toUpperCase();
  return entries.find((entry) => entry.suffix === normalizedSuffix) || null;
}