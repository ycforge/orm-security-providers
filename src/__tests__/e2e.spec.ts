import { jest } from "@jest/globals";
import { KmsEncryptionProvider } from "../yandex-kms/kms-encryption-provider.js";
import { KmsBlindIndexProvider } from "../hmac-bi/hmac-blind-index-provider.js";
import type { YdbEncryptionContext } from "@ycforge/ydb-orm";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.clearAllMocks();
});

/** Фабрика mock-провайдера KMS с подменённым fetch. */
function createMockKmsProviders() {
  const keyId = "test-key-id";

  const encProvider = new KmsEncryptionProvider({
    keyId,
    auth_type: "iam_token",
    authOptions: { iam_token: "test-token" },
  });

  const biProvider = new KmsBlindIndexProvider({
    blindIndexKey: Buffer.alloc(32).toString("base64"),
  });

  const mockFetch = jest.fn((url: string, init: any) => {
    const body = JSON.parse(init.body);

    if (String(url).includes(":encrypt")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            keyId,
            versionId: "v1",
            ciphertext: `kms:${body.plaintext}`,
          }),
        text: () => Promise.resolve(""),
      } as Response);
    }

    if (String(url).includes(":decrypt")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            keyId,
            versionId: "v1",
            plaintext: body.ciphertext.replace(/^kms:/, ""),
          }),
        text: () => Promise.resolve(""),
      } as Response);
    }

    return Promise.resolve({
      ok: false,
      status: 404,
      json: () => Promise.resolve({}),
      text: () => Promise.resolve("Not found"),
    } as Response);
  });

  return { encProvider, biProvider, mockFetch };
}

const context: YdbEncryptionContext = {
  entityName: "UserEntity",
  tableName: "users",
  fieldName: "email",
  primaryKeyValue: "uuid-abc",
  aadFields: { organization: "Acme Corp" },
};

describe("E2E: KMS encrypt → decrypt roundtrip (mocked)", () => {
  it("full cycle: encrypt → decrypt returns original plaintext", async () => {
    const { encProvider, mockFetch } = createMockKmsProviders();
    globalThis.fetch = mockFetch as any;

    const plaintext = "user@example.com";
    const aad = "organization=Acme Corp";

    const ciphertext = await encProvider.encrypt(plaintext, aad, context);
    const decrypted = await encProvider.decrypt(ciphertext, aad, context);

    expect(decrypted).toBe(plaintext);
  });

  it("full cycle: encrypt → blind index → search", async () => {
    const { encProvider, biProvider, mockFetch } = createMockKmsProviders();
    globalThis.fetch = mockFetch as any;

    const plaintext = "search@example.com";
    const aad = "organization=Acme Corp";

    const ciphertext = await encProvider.encrypt(plaintext, aad, context);
    const blindIndex = await biProvider.hash(plaintext, context);

    expect(ciphertext).not.toBe(plaintext);
    expect(blindIndex).not.toBe(plaintext);

    const decrypted = await encProvider.decrypt(ciphertext, aad, context);
    expect(decrypted).toBe(plaintext);
  });

  it("different AAD produces different ciphertext", async () => {
    const { encProvider } = createMockKmsProviders();

    // Override mock to include AAD in ciphertext
    globalThis.fetch = jest.fn((_url: string, init: any) => {
      const body = JSON.parse(init.body);
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            keyId: "test-key-id",
            versionId: "v1",
            ciphertext: `kms:${body.plaintext}:${body.aadContext || ""}`,
          }),
        text: () => Promise.resolve(""),
      } as Response);
    }) as any;

    const c1 = await encProvider.encrypt("same@email.com", "org=Acme", context);
    const c2 = await encProvider.encrypt(
      "same@email.com",
      "org=Other",
      context,
    );

    expect(c1).not.toBe(c2);
  });

  it("handles multiple fields with different contexts", async () => {
    const { encProvider, mockFetch } = createMockKmsProviders();
    globalThis.fetch = mockFetch as any;

    const emailCtx: YdbEncryptionContext = {
      entityName: "UserEntity",
      tableName: "users",
      fieldName: "email",
      aadFields: {},
    };
    const phoneCtx: YdbEncryptionContext = {
      entityName: "UserEntity",
      tableName: "users",
      fieldName: "phone",
      aadFields: {},
    };

    const email = await encProvider.encrypt("user@test.com", "", emailCtx);
    const phone = await encProvider.encrypt("+7-999-123-4567", "", phoneCtx);

    const emailDec = await encProvider.decrypt(email, "", emailCtx);
    const phoneDec = await encProvider.decrypt(phone, "", phoneCtx);

    expect(emailDec).toBe("user@test.com");
    expect(phoneDec).toBe("+7-999-123-4567");
  });

  it("blind index is consistent across multiple calls", async () => {
    const { biProvider } = createMockKmsProviders();

    for (const value of ["a@b.com", "c@d.com", "", "Привет"]) {
      const h1 = await biProvider.hash(value, context);
      const h2 = await biProvider.hash(value, context);
      expect(h1).toBe(h2);
    }
  });

  it("KMS API errors propagate correctly", async () => {
    const { encProvider } = createMockKmsProviders();

    globalThis.fetch = jest.fn(() =>
      Promise.resolve({
        ok: false,
        status: 400,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve("Bad request"),
      } as Response),
    );

    await expect(encProvider.encrypt("data", "", context)).rejects.toThrow(
      "KMS encrypt failed: 400",
    );

    await expect(encProvider.decrypt("data", "", context)).rejects.toThrow(
      "KMS decrypt failed: 400",
    );
  });
});
