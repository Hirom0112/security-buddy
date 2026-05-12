import { describe, it, expect } from "vitest";
import { verifyOperatorPassword } from "../../src/lib/auth/password";

describe("verifyOperatorPassword", () => {
  it("returns true when input matches expected", () => {
    expect(verifyOperatorPassword("correct-password", "correct-password")).toBe(true);
  });

  it("returns false when input does not match expected", () => {
    expect(verifyOperatorPassword("wrong-password", "correct-password")).toBe(false);
  });

  it("returns false when input is empty", () => {
    expect(verifyOperatorPassword("", "correct-password")).toBe(false);
  });

  it("returns false when expected is empty and input is not", () => {
    expect(verifyOperatorPassword("some-password", "")).toBe(false);
  });

  it("returns true when both are empty strings", () => {
    // Both empty — identical, so equal. Edge case.
    expect(verifyOperatorPassword("", "")).toBe(true);
  });

  it("is case-sensitive", () => {
    expect(verifyOperatorPassword("Password", "password")).toBe(false);
    expect(verifyOperatorPassword("PASSWORD", "password")).toBe(false);
  });

  it("returns false when input is a prefix of expected", () => {
    expect(verifyOperatorPassword("correct", "correct-password")).toBe(false);
  });

  it("returns false when input is a superset of expected", () => {
    expect(verifyOperatorPassword("correct-password-extra", "correct-password")).toBe(false);
  });

  it("handles unicode correctly", () => {
    const pw = "pässwörd"; // "pässwörd"
    expect(verifyOperatorPassword(pw, pw)).toBe(true);
    expect(verifyOperatorPassword("passw0rd", pw)).toBe(false);
  });

  it("handles a long password without throwing", () => {
    const long = "a".repeat(1024);
    expect(verifyOperatorPassword(long, long)).toBe(true);
    expect(verifyOperatorPassword(long, "a".repeat(1023))).toBe(false);
  });
});
