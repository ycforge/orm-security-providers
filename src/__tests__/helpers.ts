import type { KmsAuthMethod } from "../yandex-kms/iam-token-manager.js";
import type { KmsEncryptionProviderOptions } from "../yandex-kms/kms-encryption-provider.js";
import type { KmsBlindIndexProviderOptions } from "../hmac-bi/hmac-blind-index-provider.js";

export interface KmsTestConfig {
  encryption: KmsEncryptionProviderOptions;
  blindIndex: KmsBlindIndexProviderOptions;
}

/**
 * Читает конфигурацию KMS из переменных окружения.
 *
 * Используется integration-тестами: если хотя бы одна обязательная
 * переменная не задана, entire suite пропускается через `describe.skip`.
 */
export function loadKmsTestConfigFromEnv(): KmsTestConfig | null {
  const keyId = process.env.KMS_KEY_ID;
  const authType = process.env.KMS_AUTH_TYPE as KmsAuthMethod | undefined;
  const biKey = process.env.KMS_BLIND_INDEX_KEY;

  if (!keyId || !authType || !biKey) {
    return null;
  }

  const authOptions: Record<string, string> = {};

  switch (authType) {
    case "iam_token":
      authOptions.iam_token = process.env.KMS_IAM_TOKEN ?? "";
      break;
    case "auth_key":
      authOptions.authorized_key_path =
        process.env.KMS_AUTHORIZED_KEY_PATH ?? "";
      break;
    case "meta":
      break;
    default:
      return null;
  }

  return {
    encryption: {
      keyId,
      auth_type: authType,
      authOptions,
    },
    blindIndex: {
      blindIndexKey: biKey,
    },
  };
}
