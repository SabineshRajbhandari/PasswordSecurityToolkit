const SHA1_HEX_LENGTH = 40;
const HIBP_PREFIX_LENGTH = 5;

function getCryptoApi(cryptoApi) {
  const api = cryptoApi || globalThis.crypto;
  if (!api?.subtle?.digest) {
    throw new Error("Local cryptographic hashing is unavailable in this browser.");
  }
  return api;
}

export async function hashPasswordForHibp(password, cryptoApi) {
  if (typeof password !== "string") {
    throw new TypeError("A password string is required for breach checking.");
  }

  const bytes = new TextEncoder().encode(password);
  const digest = await getCryptoApi(cryptoApi).subtle.digest("SHA-1", bytes);
  const hash = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();

  if (hash.length !== SHA1_HEX_LENGTH) {
    throw new Error("Local password hashing returned an invalid result.");
  }

  return {
    prefix: hash.slice(0, HIBP_PREFIX_LENGTH),
    suffix: hash.slice(HIBP_PREFIX_LENGTH),
  };
}