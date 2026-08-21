const COMMON_PASSWORDS = new Set([
  "123456", "password", "123456789", "12345678", "qwerty", "1234567", "111111",
  "123123", "abc123", "password1", "iloveyou", "admin", "letmein", "welcome",
  "monkey", "dragon", "football", "baseball", "master", "login", "princess",
  "starwars", "qwertyuiop", "asdfghjkl", "sunshine", "trustno1", "passw0rd",
  "p@ssword", "p@ssw0rd", "whatever", "freedom", "secret", "computer", "internet",
  "summer", "winter", "spring", "autumn", "hello", "shadow", "superman", "michael",
  "jordan", "charlie", "donald", "password123", "qwerty123", "admin123", "welcome1",
]);

export const COMMON_WORDS = new Set([
  "admin", "baseball", "charlie", "computer", "dragon", "football", "hello", "letmein",
  "login", "master", "monkey", "password", "princess", "qwerty", "secret", "shadow",
  "sunshine", "superman", "welcome", "whatever",
]);

export function normalizeForLookup(value) {
  return value.normalize("NFKC").trim().toLowerCase();
}

export function isCommonPassword(password) {
  if (typeof password !== "string" || password.length === 0) return false;
  return COMMON_PASSWORDS.has(normalizeForLookup(password));
}