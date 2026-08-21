import { hashPasswordForHibp } from "./hibpHashing.js";
import { findBreachMatch, parseHibpResponse } from "./hibpParser.js";

export const HIBP_RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range/";

export async function checkPasswordBreach(password, {
  fetchImplementation = globalThis.fetch,
  cryptoApi,
  endpoint = HIBP_RANGE_ENDPOINT,
} = {}) {
  if (typeof fetchImplementation !== "function") {
    throw new Error("Breach-check network access is unavailable.");
  }

  const { prefix, suffix } = await hashPasswordForHibp(password, cryptoApi);
  const response = await fetchImplementation(`${endpoint}${prefix}`, {
    method: "GET",
    headers: { "Add-Padding": "true" },
  });

  if (response.status === 429) {
    throw new Error("Breach check temporarily unavailable. Please try again later.");
  }
  if (!response.ok) {
    throw new Error("Unable to contact the breach-check service.");
  }

  const entries = parseHibpResponse(await response.text());
  const match = findBreachMatch(entries, suffix);
  return match
    ? { status: "found", count: match.count }
    : { status: "not_found" };
}