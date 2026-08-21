import { jest } from "@jest/globals";
import { KmsEncryptionProvider } from "../yandex-kms/kms-encryption-provider.js";
import type { YdbEncryptionContext } from "@ycforge/ydb-orm";

const originalFetch = globalThis.fetch;

const defaultContext: YdbEncryptionContext = {
  entityName: "UserEntity",
  tableName: "users",
  fieldName: "email",
  primaryKeyValue: "uuid-123",
  aadFields: { organization: "Acme" },
};

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

function errorResponse(status: number, body: string): Response {
  return {
    ok: false,
    status,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(body),
  } as Response;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.clearAllMocks();
});

describe("KmsEncryptionProvider", () => {
  const baseOpts = {
    keyId: "aby123key",
    auth_type: "iam_token" as const,
    authOptions: { iam_token: "test-token" },
  };

  describe("constructor", () => {
    it("creates provider with required options", () => {
      const provider = new KmsEncryptionProvider(baseOpts);
      expect(provider).toBeDefined();
    });

    it("throws when keyId is empty", () => {
      expect(
        () =>
          new KmsEncryptionProvider({
            ...baseOpts,
            keyId: "",
          }),
      ).toThrow("keyId is required");
    });

    it("uses custom apiEndpoint", () => {
      const provider = new KmsEncryptionProvider({
        ...baseOpts,
        apiEndpoint: "https://custom-kms.example.com",
      });
      expect(provider).toBeDefined();
    });
  });

  describe("encrypt", () => {
    it("calls KMS encrypt API and returns raw ciphertext as Uint8Array", async () => {
      const kmsCiphertextBase64 =
        Buffer.from("raw-ciphertext").toString("base64");
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            ciphertext: kmsCiphertextBase64,
          }),
        ),
      );

      const provider = new KmsEncryptionProvider(baseOpts);
      const result = await provider.encrypt("hello world", "", defaultContext);

      // Контракт ORM v0.2+: наружу — raw bytes, а не base64-строка
      expect(result).toBeInstanceOf(Uint8Array);
      expect(Buffer.from(result).toString("utf8")).toBe("raw-ciphertext");

      expect(globalThis.fetch).toHaveBeenCalledWith(
        "https://kms.yandex/kms/v1/keys/aby123key:encrypt",
        expect.objectContaining({
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer test-token",
          },
        }),
      );

      const body = JSON.parse(
        ((globalThis.fetch as jest.Mock).mock.calls[0][1] as RequestInit)
          .body as string,
      );
      expect(body.plaintext).toBe(
        Buffer.from("hello world", "utf8").toString("base64"),
      );
      expect(body.aadContext).toBeUndefined();
    });

    it("includes aadContext when AAD is provided", async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            ciphertext: Buffer.from("enc-with-aad").toString("base64"),
          }),
        ),
      );

      const provider = new KmsEncryptionProvider(baseOpts);
      await provider.encrypt("secret", "org=Acme", defaultContext);

      const body = JSON.parse(
        ((globalThis.fetch as jest.Mock).mock.calls[0][1] as RequestInit)
          .body as string,
      );
      expect(body.aadContext).toBe(
        Buffer.from("org=Acme", "utf8").toString("base64"),
      );
    });

    it("throws on non-200 response", async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(errorResponse(403, "Permission denied")),
      );

      const provider = new KmsEncryptionProvider(baseOpts);

      await expect(
        provider.encrypt("data", "", defaultContext),
      ).rejects.toThrow("KMS encrypt failed: 403");
    });

    it("uses iam_token auth by default", async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            ciphertext: Buffer.from("result").toString("base64"),
          }),
        ),
      );

      const provider = new KmsEncryptionProvider(baseOpts);
      await provider.encrypt("x", "", defaultContext);

      const init = (globalThis.fetch as jest.Mock).mock
        .calls[0][1] as RequestInit;
      expect((init.headers as Record<string, string>).Authorization).toBe(
        "Bearer test-token",
      );
    });
  });

  describe("decrypt", () => {
    it("sends base64(ciphertext) to KMS and returns UTF-8 plaintext", async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            plaintext: Buffer.from("hello world", "utf8").toString("base64"),
          }),
        ),
      );

      const provider = new KmsEncryptionProvider(baseOpts);
      const ciphertext = new Uint8Array(
        Buffer.from("base64-ciphertext-source", "utf8"),
      );
      const result = await provider.decrypt(ciphertext, "", defaultContext);

      expect(result).toBe("hello world");
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "https://kms.yandex/kms/v1/keys/aby123key:decrypt",
        expect.objectContaining({ method: "POST" }),
      );

      const body = JSON.parse(
        ((globalThis.fetch as jest.Mock).mock.calls[0][1] as RequestInit)
          .body as string,
      );
      expect(body.ciphertext).toBe(
        Buffer.from("base64-ciphertext-source", "utf8").toString("base64"),
      );
      expect(body.aadContext).toBeUndefined();
    });

    it("includes aadContext when AAD is provided", async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            plaintext: Buffer.from("decrypted", "utf8").toString("base64"),
          }),
        ),
      );

      const provider = new KmsEncryptionProvider(baseOpts);
      await provider.decrypt(
        new Uint8Array([1, 2, 3]),
        "org=Acme",
        defaultContext,
      );

      const body = JSON.parse(
        ((globalThis.fetch as jest.Mock).mock.calls[0][1] as RequestInit)
          .body as string,
      );
      expect(body.aadContext).toBe(
        Buffer.from("org=Acme", "utf8").toString("base64"),
      );
    });

    it("throws on non-200 response", async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(errorResponse(400, "Invalid ciphertext")),
      );

      const provider = new KmsEncryptionProvider(baseOpts);

      await expect(
        provider.decrypt(new Uint8Array([9]), "", defaultContext),
      ).rejects.toThrow("KMS decrypt failed: 400");
    });

    it("handles UTF-8 characters correctly", async () => {
      const utf8Text = "Привет мир 🌍";
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            plaintext: Buffer.from(utf8Text, "utf8").toString("base64"),
          }),
        ),
      );

      const provider = new KmsEncryptionProvider(baseOpts);
      const result = await provider.decrypt(
        new Uint8Array([1]),
        "",
        defaultContext,
      );

      expect(result).toBe(utf8Text);
    });
  });

  describe("encrypt → decrypt roundtrip", () => {
    it("preserves data through raw-byte ciphertext (Uint8Array)", async () => {
      globalThis.fetch = jest.fn((url: string | URL | Request, init?: any) => {
        const body = JSON.parse(init.body);

        const urlText =
          typeof url === "string"
            ? url
            : url instanceof URL
              ? url.href
              : url.url;
        if (urlText.includes(":encrypt")) {
          return Promise.resolve(
            jsonResponse({
              keyId: "aby123key",
              versionId: "v1",
              // KMS возвращает base64(plaintext) — имитируем «шифрование»
              ciphertext: body.plaintext,
            }),
          );
        }

        return Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            plaintext: body.ciphertext,
          }),
        );
      }) as any;

      const provider = new KmsEncryptionProvider(baseOpts);

      const encrypted: Uint8Array = await provider.encrypt(
        "test data",
        "aad-value",
        defaultContext,
      );
      expect(encrypted).toBeInstanceOf(Uint8Array);

      const decrypted = await provider.decrypt(
        encrypted,
        "aad-value",
        defaultContext,
      );

      expect(decrypted).toBe("test data");
    });

    it("roundtrips multibyte UTF-8 plaintext through binary ciphertext", async () => {
      const text = "данные 🌍 data";
      // «KMS»: base64(ciphertext) → base64(plaintext); шифротекст — случайные байты
      const vault = new Map<string, string>();
      globalThis.fetch = jest.fn((url: string | URL | Request, init?: any) => {
        const body = JSON.parse(init!.body);

        const urlText =
          typeof url === "string"
            ? url
            : url instanceof URL
              ? url.href
              : url.url;
        if (urlText.includes(":encrypt")) {
          const ct = Buffer.from(
            Array.from({ length: 48 }, (_, i) => (i * 37 + 11) % 256),
          ).toString("base64");
          vault.set(ct, body.plaintext);
          return Promise.resolve(
            jsonResponse({
              keyId: "aby123key",
              versionId: "v1",
              ciphertext: ct,
            }),
          );
        }

        return Promise.resolve(
          jsonResponse({
            keyId: "aby123key",
            versionId: "v1",
            plaintext: vault.get(body.ciphertext)!,
          }),
        );
      }) as any;

      const provider = new KmsEncryptionProvider(baseOpts);
      const ciphertext = await provider.encrypt(text, "", defaultContext);
      expect(ciphertext).toBeInstanceOf(Uint8Array);
      const decrypted = await provider.decrypt(ciphertext, "", defaultContext);
      expect(decrypted).toBe(text);
    });
  });
});
