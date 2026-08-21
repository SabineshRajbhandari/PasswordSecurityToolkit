import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";
import { checkPasswordBreach } from "../src/breach/hibpClient.js";
import { hashPasswordForHibp } from "../src/breach/hibpHashing.js";
import { findBreachMatch, parseHibpResponse } from "../src/breach/hibpParser.js";

const cryptoApi = webcrypto;
const realFetch = globalThis.fetch;

test("hashes the known SHA-1 vector and splits prefix and suffix correctly", async () => {
  const result = await hashPasswordForHibp("test", cryptoApi);
  assert.equal(result.prefix, "A94A8");
  assert.equal(result.suffix, "FE5CCB19BA61C4C0873D391E987982FBBD3");
  assert.equal(result.prefix.length, 5);
  assert.equal(result.suffix.length, 35);
});

test("hash output is uppercase and encodes Unicode locally", async () => {
  const result = await hashPasswordForHibp("pässw🔐rd", cryptoApi);
  assert.match(result.prefix, /^[A-F0-9]{5}$/);
  assert.match(result.suffix, /^[A-F0-9]{35}$/);
});

test("parses multiple HIBP entries and matches suffix case-insensitively", () => {
  const entries = parseHibpResponse("ABCDEF0123456789ABCDEF0123456789ABC:12\nfe5ccb19ba61c4c0873d391e987982fbbd3:987");
  assert.equal(entries.length, 2);
  assert.deepEqual(findBreachMatch(entries, "FE5CCB19BA61C4C0873D391E987982FBBD3"), {
    suffix: "FE5CCB19BA61C4C0873D391E987982FBBD3",
    count: 987,
  });
  assert.equal(findBreachMatch(entries, "00000000000000000000000000000000000"), null);
});

test("rejects malformed HIBP responses", () => {
  assert.throws(() => parseHibpResponse("not-a-valid-entry"));
  assert.throws(() => parseHibpResponse("ABCDEF0123456789ABCDEF0123456789ABC:NaN"));
  assert.deepEqual(parseHibpResponse(""), []);
});

test("sends only the five-character prefix and returns found count", async () => {
  let requestedUrl = "";
  const fetchImplementation = async (url) => {
    requestedUrl = url;
    return new Response("FE5CCB19BA61C4C0873D391E987982FBBD3:12345\nABCDEF0123456789ABCDEF0123456789ABC:2", { status: 200 });
  };

  const result = await checkPasswordBreach("test", { fetchImplementation, cryptoApi });
  assert.equal(result.status, "found");
  assert.equal(result.count, 12345);
  assert.equal(requestedUrl, "https://api.pwnedpasswords.com/range/A94A8");
  assert.equal(requestedUrl.includes("A94A8FE5"), false);
  assert.equal(requestedUrl.includes("test"), false);
  assert.equal(JSON.stringify(result).includes("test"), false);
});

test("returns not found only after a valid successful response", async () => {
  const result = await checkPasswordBreach("test", {
    fetchImplementation: async () => new Response("ABCDEF0123456789ABCDEF0123456789ABC:2", { status: 200 }),
    cryptoApi,
  });
  assert.deepEqual(result, { status: "not_found" });

  const emptyResult = await checkPasswordBreach("test", {
    fetchImplementation: async () => new Response("", { status: 200 }),
    cryptoApi,
  });
  assert.deepEqual(emptyResult, { status: "not_found" });
});

test("handles network, HTTP, rate-limit, malformed, and unsupported-crypto failures", async () => {
  await assert.rejects(
    checkPasswordBreach("test", { fetchImplementation: async () => { throw new Error("offline"); }, cryptoApi }),
    /offline/,
  );
  await assert.rejects(
    checkPasswordBreach("test", { fetchImplementation: async () => new Response("", { status: 500 }), cryptoApi }),
    /Unable to contact/,
  );
  await assert.rejects(
    checkPasswordBreach("test", { fetchImplementation: async () => new Response("", { status: 429 }), cryptoApi }),
    /temporarily unavailable/,
  );
  await assert.rejects(
    checkPasswordBreach("test", { fetchImplementation: async () => new Response("bad", { status: 200 }), cryptoApi }),
    /invalid response/,
  );
  await assert.rejects(
    checkPasswordBreach("test", { fetchImplementation: async () => new Response("", { status: 200 }), cryptoApi: {} }),
    /cryptographic hashing is unavailable/,
  );
});

test("breach checking does not use global fetch or browser persistence", async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return new Response("bad", { status: 200 });
  };
  try {
    await checkPasswordBreach("test", { fetchImplementation: realFetch, cryptoApi }).catch(() => {});
    assert.equal(called, false);
    assert.equal("localStorage" in globalThis, false);
    assert.equal("sessionStorage" in globalThis, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});