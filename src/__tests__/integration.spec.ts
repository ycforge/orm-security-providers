/**
 * Integration-тесты: реальный KMS API Yandex Cloud.
 *
 * Запуск:
 *   KMS_KEY_ID=aby... KMS_AUTH_TYPE=iam_token KMS_IAM_TOKEN=... KMS_BLIND_INDEX_KEY=... yarn test:integration
 *
 * Если переменные не заданы — suite пропускается (skip).
 * Никаких секретов в коде: всё читается из ENV.
 */
import { KmsEncryptionProvider } from "../yandex-kms/kms-encryption-provider.js";
import { KmsBlindIndexProvider } from "../hmac-bi/hmac-blind-index-provider.js";
import { loadKmsTestConfigFromEnv } from "./helpers.js";
import type { YdbEncryptionContext } from "@ycforge/ydb-orm";

const config = loadKmsTestConfigFromEnv();

const context: YdbEncryptionContext = {
  entityName: "UserEntity",
  tableName: "users",
  fieldName: "email",
  primaryKeyValue: "integration-test",
  aadFields: {},
};

function providers() {
  return {
    enc: new KmsEncryptionProvider(config!.encryption),
    bi: new KmsBlindIndexProvider(config!.blindIndex),
  };
}

describe("Integration: Yandex Cloud KMS (real API)", () => {
  if (!config) {
    it.skip("skipped: KMS_KEY_ID / KMS_AUTH_TYPE / KMS_BLIND_INDEX_KEY not set", () => {});
    return;
  }

  it("encrypt and decrypt roundtrip", async () => {
    const { enc } = providers();
    const plaintext = "integration-test@example.com";

    const ciphertext = await enc.encrypt(plaintext, "", context);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(ciphertext).toString("utf8")).not.toBe(plaintext);

    const decrypted = await enc.decrypt(ciphertext, "", context);
    expect(decrypted).toBe(plaintext);
  });

  it("encrypt with AAD and decrypt roundtrip", async () => {
    const { enc } = providers();
    const plaintext = "aad-test@example.com";
    const aad = "organization=IntegrationTest";

    const ciphertext = await enc.encrypt(plaintext, aad, context);
    const decrypted = await enc.decrypt(ciphertext, aad, context);

    expect(decrypted).toBe(plaintext);
  });

  it("decrypt with wrong AAD fails", async () => {
    const { enc } = providers();
    const plaintext = "aad-bound@example.com";

    const ciphertext = await enc.encrypt(plaintext, "org=Correct", context);

    await expect(
      enc.decrypt(ciphertext, "org=Wrong", context),
    ).rejects.toThrow();
  });

  it("blind index is deterministic", async () => {
    const { bi } = providers();
    const value = "deterministic@example.com";

    const h1 = await bi.hash(value, context);
    const h2 = await bi.hash(value, context);

    expect(h1).toBe(h2);
    expect(h1.length).toBeGreaterThan(0);
  });

  it("different values produce different blind indexes", async () => {
    const { bi } = providers();

    const h1 = await bi.hash("alice@example.com", context);
    const h2 = await bi.hash("bob@example.com", context);

    expect(h1).not.toBe(h2);
  });

  it("handles UTF-8 correctly", async () => {
    const { enc } = providers();
    const plaintext = "Тест шифрования 🌍";

    const ciphertext = await enc.encrypt(plaintext, "", context);
    const decrypted = await enc.decrypt(ciphertext, "", context);

    expect(decrypted).toBe(plaintext);
  });
});
