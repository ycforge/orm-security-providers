import { KmsBlindIndexProvider } from "../hmac-bi/hmac-blind-index-provider.js";
import type { YdbEncryptionContext } from "@ycforge/ydb-orm";

const defaultContext: YdbEncryptionContext = {
  entityName: "UserEntity",
  tableName: "users",
  fieldName: "email",
  primaryKeyValue: "uuid-123",
  aadFields: {},
};

describe("KmsBlindIndexProvider", () => {
  describe("constructor", () => {
    it("creates provider with valid base64 key", () => {
      const key = Buffer.alloc(32).toString("base64");
      const provider = new KmsBlindIndexProvider({ blindIndexKey: key });
      expect(provider).toBeDefined();
    });

    it("throws when blindIndexKey is empty", () => {
      expect(() => new KmsBlindIndexProvider({ blindIndexKey: "" })).toThrow(
        "blindIndexKey is required",
      );
    });

    it("throws when key is shorter than 32 bytes", () => {
      const shortKey = Buffer.alloc(16).toString("base64");
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: shortKey }),
      ).toThrow("at least 32 bytes");
    });

    it("accepts exactly 32-byte key", () => {
      const key = Buffer.alloc(32).toString("base64");
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: key }),
      ).not.toThrow();
    });

    it("accepts longer keys", () => {
      const key = Buffer.alloc(64).toString("base64");
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: key }),
      ).not.toThrow();
    });

    it("tolerates surrounding whitespace (env-friendly)", () => {
      const key = Buffer.alloc(32).toString("base64");
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: `  ${key}\n` }),
      ).not.toThrow();
    });

    it("rejects strings with characters outside the Base64 alphabet", () => {
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: "not-base64!!!" }),
      ).toThrow(/valid canonical Base64/);
    });

    it("rejects padding in the middle of the string", () => {
      const key = Buffer.alloc(32).toString("base64");
      const broken = `${key.slice(0, 4)}=${key.slice(5)}`;
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: broken }),
      ).toThrow(/valid canonical Base64/);
    });

    it("rejects non-canonical trailing bits", () => {
      // "AB==" декодируется в байт, но канонично это "AA==" — lenient-декодер
      // Node молча теряет хвостовые биты; строгая проверка это отсекает.
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: "AB==" }),
      ).toThrow(/valid canonical Base64/);
    });

    it("rejects unpadded keys whose length requires padding", () => {
      const padded = Buffer.alloc(32).toString("base64"); // 44 chars, оканчивается на '='
      const unpadded = padded.replace(/=+$/, "");
      expect(unpadded.length).toBe(43);
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: unpadded }),
      ).toThrow(/valid canonical Base64/);
    });

    it("rejects impossible Base64 lengths (len % 4 === 1)", () => {
      const key = `${Buffer.alloc(32).toString("base64")}e`;
      expect(key.length % 4).toBe(1);
      expect(() => new KmsBlindIndexProvider({ blindIndexKey: key })).toThrow(
        /valid canonical Base64/,
      );
    });
  });

  describe("hash", () => {
    const key = Buffer.from(
      "0123456789abcdef0123456789abcdef",
      "utf8",
    ).toString("base64");
    const provider = new KmsBlindIndexProvider({ blindIndexKey: key });

    it("returns a base64-encoded HMAC-SHA256 hash", async () => {
      const hash = await provider.hash("test@example.com", defaultContext);

      expect(typeof hash).toBe("string");
      expect(hash.length).toBeGreaterThan(0);
      // base64 of 32 bytes = 44 chars
      expect(hash.length).toBe(44);
    });

    it("is deterministic: same input produces same output", async () => {
      const h1 = await provider.hash("test@example.com", defaultContext);
      const h2 = await provider.hash("test@example.com", defaultContext);

      expect(h1).toBe(h2);
    });

    it("produces different hashes for different inputs", async () => {
      const h1 = await provider.hash("alice@example.com", defaultContext);
      const h2 = await provider.hash("bob@example.com", defaultContext);

      expect(h1).not.toBe(h2);
    });

    it("ignores context parameter", async () => {
      const ctx1: YdbEncryptionContext = {
        entityName: "UserEntity",
        tableName: "users",
        fieldName: "email",
        primaryKeyValue: "uuid-1",
        aadFields: {},
      };
      const ctx2: YdbEncryptionContext = {
        entityName: "AdminEntity",
        tableName: "admins",
        fieldName: "login",
        primaryKeyValue: "uuid-2",
        aadFields: { role: "admin" },
      };

      const h1 = await provider.hash("same-value", ctx1);
      const h2 = await provider.hash("same-value", ctx2);

      expect(h1).toBe(h2);
    });

    it("produces different hashes with different keys", async () => {
      const key2 = Buffer.from(
        "abcdef0123456789abcdef0123456789",
        "utf8",
      ).toString("base64");
      const provider2 = new KmsBlindIndexProvider({ blindIndexKey: key2 });

      const h1 = await provider.hash("same", defaultContext);
      const h2 = await provider2.hash("same", defaultContext);

      expect(h1).not.toBe(h2);
    });

    it("handles empty string input", async () => {
      const hash = await provider.hash("", defaultContext);
      expect(typeof hash).toBe("string");
      expect(hash.length).toBe(44);
    });

    it("handles Unicode input", async () => {
      const hash = await provider.hash("Привет 🌍", defaultContext);
      expect(typeof hash).toBe("string");
      expect(hash.length).toBe(44);
    });

    // Эталонные значения посчитаны внешним инструментом (python hmac/sha256)
    // по base64-декодированному ключу — проверяют, что это именно
    // HMAC-SHA256(key=base64decode(blindIndexKey)), а не что-то другое.
    it.each([
      ["alice@example.com", "hBJA0qW2ZUs64h/ESZ23t4Zwd83WfD4WzvH5hD4n0fo="],
      ["", "eWzTB4rxRjZ1PSaztVVUIv9Vo+Jhz4R7SOlTcbm9CqI="],
      ["Привет 🌍", "hXl70PFlH0kifuhCLTCko0NZdhSgOtcYGuhnXxygv00="],
    ])("matches reference HMAC-SHA256 for %j", async (plaintext, expected) => {
      const key = Buffer.from(
        "0123456789abcdef0123456789abcdef",
        "utf8",
      ).toString("base64");
      const p = new KmsBlindIndexProvider({ blindIndexKey: key });
      expect(await p.hash(plaintext, defaultContext)).toBe(expected);
    });

    it("treats equal plaintexts as equal indexes regardless of context/entity", async () => {
      const h = await provider.hash("equal@example.com", defaultContext);
      const h2 = await provider.hash(
        "equal@example.com",
        {} as YdbEncryptionContext,
      );
      expect(h).toBe(h2);
    });
  });
});
