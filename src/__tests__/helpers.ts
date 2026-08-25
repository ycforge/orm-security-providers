import { existsSync } from "node:fs";
import { createAuth, authKeyFromFile } from "@ycforge/auth";
import type { KmsEncryptionProviderOptions } from "../yandex-kms/kms-encryption-provider.js";
import type { KmsBlindIndexProviderOptions } from "../hmac-bi/hmac-blind-index-provider.js";

export interface KmsTestConfig {
  encryption: KmsEncryptionProviderOptions;
  blindIndex: KmsBlindIndexProviderOptions;
}

/**
 * Читает конфигурацию KMS из переменных окружения и создаёт готовый
 * {@link AuthManager} через `@ycforge/auth`.
 *
 * Используется integration-тестами: если хотя бы одна обязательная
 * переменная не задана (или указанный ключевой файл не существует),
 * entire suite пропускается через `describe.skip`.
 */
export function loadKmsTestConfigFromEnv(): KmsTestConfig | null {
  const keyId = process.env.KMS_KEY_ID;
  const authType = process.env.KMS_AUTH_TYPE;
  const biKey = process.env.KMS_BLIND_INDEX_KEY;

  if (!keyId || !authType || !biKey) {
    return null;
  }

  const auth = ((): ReturnType<typeof createAuth> | null => {
    switch (authType) {
      case "iam_token": {
        const token = process.env.KMS_IAM_TOKEN ?? "";
        if (!token) return null;
        const expiresAt = process.env.KMS_IAM_TOKEN_EXPIRES_AT;
        return createAuth({
          type: "iam_token",
          token,
          ...(expiresAt ? { expiresAt } : {}),
        });
      }
      case "auth_key": {
        const path = process.env.KMS_AUTHORIZED_KEY_PATH ?? "";
        if (!path || !existsSync(path)) return null;
        return createAuth(authKeyFromFile(path));
      }
      case "metadata":
        return createAuth({ type: "metadata" });
      default:
        return null;
    }
  })();

  if (!auth) {
    return null;
  }

  return {
    encryption: {
      keyId,
      auth,
    },
    blindIndex: {
      blindIndexKey: biKey,
    },
  };
}
