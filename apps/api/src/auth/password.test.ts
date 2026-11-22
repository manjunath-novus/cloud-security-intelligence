
import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./password.js";

describe("Password security", () => {
  it("should hash and verify a correct password", async () => {
    const hash = await hashPassword("StrongPassword123!");

    expect(hash).not.toBe("StrongPassword123!");
    expect(await verifyPassword("StrongPassword123!", hash)).toBe(true);
  });

  it("should reject an incorrect password", async () => {
    const hash = await hashPassword("StrongPassword123!");

    expect(await verifyPassword("WrongPassword123!", hash)).toBe(false);
  });

  it("should generate different hashes for the same password", async () => {
    const firstHash = await hashPassword("StrongPassword123!");
    const secondHash = await hashPassword("StrongPassword123!");

    expect(firstHash).not.toBe(secondHash);
    expect(await verifyPassword("StrongPassword123!", firstHash)).toBe(true);
    expect(await verifyPassword("StrongPassword123!", secondHash)).toBe(true);
  });
});
