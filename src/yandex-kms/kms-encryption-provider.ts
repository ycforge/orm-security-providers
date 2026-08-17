import type {
  YdbEncryptionProvider,
  YdbEncryptionContext,
} from "@ycforge/ydb-orm";
import { IamTokenManager } from "./iam-token-manager.js";
import type { KmsAuthMethod, KmsAuthOptions } from "./iam-token-manager.js";

const KMS_API_BASE = "https://kms.yandex";

interface KmsEncryptResponse {
  keyId: string;
  versionId: string;
  ciphertext: string;
}

interface KmsDecryptResponse {
  keyId: string;
  versionId: string;
  plaintext: string;
}

export interface KmsEncryptionProviderOptions {
  /** ID симметричного ключа Yandex Cloud KMS. */
  keyId: string;
  /** Способ авторизации. */
  auth_type: KmsAuthMethod;
  /** Опции авторизации. */
  authOptions: KmsAuthOptions;
  /** Базовый URL KMS API (по умолчанию https://kms.yandex). */
  apiEndpoint?: string;
}

/**
 * Провайдер шифрования для @ycforge/ydb-orm на базе Yandex Cloud KMS.
 *
 * Использует REST API SymmetricCrypto (encrypt/decrypt) для шифрования
 * и дешифрования полей сущностей. AAD (Additional Authenticated Data)
 * передаётся как aadContext — привязывает ciphertext к значениям
 * @YdbSecurityAAD-полей.
 *
 * Подключается через опции модуля:
 *
 * ```ts
 * encryptionProvider: new KmsEncryptionProvider({
 *   keyId: 'aby...",
 *   auth_type: 'auth_key',
 *   authOptions: { authorized_key_path: './authorized_key.json' },
 * }),
 * ```
 */
export class KmsEncryptionProvider implements YdbEncryptionProvider {
  readonly #keyId: string;
  readonly #tokenManager: IamTokenManager;
  readonly #apiEndpoint: string;

  constructor(options: KmsEncryptionProviderOptions) {
    if (!options.keyId) {
      throw new Error("keyId is required");
    }

    this.#keyId = options.keyId;
    this.#apiEndpoint = options.apiEndpoint ?? KMS_API_BASE;
    this.#tokenManager = new IamTokenManager(
      options.auth_type,
      options.authOptions,
    );
  }

  async encrypt(
    plaintext: string,
    aad: string,
    _context: YdbEncryptionContext,
  ): Promise<string> {
    const token = await this.#tokenManager.getToken();

    const body: Record<string, string> = {
      plaintext: Buffer.from(plaintext, "utf8").toString("base64"),
    };

    if (aad) {
      body.aadContext = Buffer.from(aad, "utf8").toString("base64");
    }

    const url = `${this.#apiEndpoint}/kms/v1/keys/${this.#keyId}:encrypt`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`KMS encrypt failed: ${response.status} ${text}`);
    }

    const data = (await response.json()) as KmsEncryptResponse;
    return data.ciphertext;
  }

  async decrypt(
    ciphertext: string,
    aad: string,
    _context: YdbEncryptionContext,
  ): Promise<string> {
    const token = await this.#tokenManager.getToken();

    const body: Record<string, string> = {
      ciphertext,
    };

    if (aad) {
      body.aadContext = Buffer.from(aad, "utf8").toString("base64");
    }

    const url = `${this.#apiEndpoint}/kms/v1/keys/${this.#keyId}:decrypt`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`KMS decrypt failed: ${response.status} ${text}`);
    }

    const data = (await response.json()) as KmsDecryptResponse;
    return Buffer.from(data.plaintext, "base64").toString("utf8");
  }
}
