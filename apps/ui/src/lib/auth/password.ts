import crypto from "crypto";

/**
 * Constant-time comparison of the operator's submitted password against
 * the expected password from the environment. Equalises buffer lengths
 * before comparing to prevent length-based timing leaks.
 */
export function verifyOperatorPassword(
  input: string,
  expected: string
): boolean {
  const inputBuf = Buffer.from(input, "utf8");
  const expectedBuf = Buffer.from(expected, "utf8");

  // If lengths differ, pad the shorter one with zeroes.
  // We still do the full timingSafeEqual to avoid length-based timing leaks.
  const maxLen = Math.max(inputBuf.length, expectedBuf.length);

  const paddedInput = Buffer.alloc(maxLen);
  const paddedExpected = Buffer.alloc(maxLen);

  inputBuf.copy(paddedInput);
  expectedBuf.copy(paddedExpected);

  const buffersMatch = crypto.timingSafeEqual(paddedInput, paddedExpected);

  // Additionally check actual lengths match so padding doesn't make
  // "abc" === "abcd" compare as equal.
  return buffersMatch && inputBuf.length === expectedBuf.length;
}
