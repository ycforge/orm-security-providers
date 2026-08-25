import type {
  YdbEncryptionProvider,
  YdbEncryptionContext,
} from '@ycforge/ydb-orm';
import { YCLOUD_AUTH_USAGE, type AuthManager } from '@ycforge/auth';

const KMS_API_BASE = 'https://kms.yandex';

interface KmsEncryptResponse {
  keyId: string;
  versionId: string;
  /** Ciphertext в base64 (формат Yandex KMS REST API). */
  ciphertext: string;
}

interface KmsDecryptResponse {
  keyId: string;
  versionId: string;
  /** Plaintext в base64 (формат Yandex KMS REST API). */
  plaintext: string;
}

export interface KmsEncryptionProviderOptions {
  /** ID симметричного ключа Yandex Cloud KMS. */
  keyId: string;
  /** Готовый менеджер авторизации из `@ycforge/auth`. */
  auth: AuthManager;
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
 * Контракт ORM (v0.2+): наружу provider отдаёт и принимает raw ciphertext
 * как Uint8Array — он хранится в YDB-колонке `Bytes` без перекодирований.
 * Base64 появляется только на границе с KMS REST API.
 *
 * Подключается через опции модуля:
 *
 * ```ts
 * import { createAuth, authKeyFromFile } from '@ycforge/auth';
 * import { KmsEncryptionProvider } from '@ycforge/orm-security-providers/yandex-kms';
 *
 * encryptionProvider: new KmsEncryptionProvider({
 *   keyId: 'aby...',
 *   auth: createAuth(authKeyFromFile('./authorized_key.json')),
 * }),
 * ```
 */
export class KmsEncryptionProvider implements YdbEncryptionProvider {
  readonly #keyId: string;
  readonly #auth: AuthManager;
  readonly #apiEndpoint: string;

  constructor(options: KmsEncryptionProviderOptions) {
    if (!options.keyId) {
      throw new Error('keyId is required');
    }

    if (!options.auth) {
      throw new Error('auth (AuthManager) is required');
    }

    this.#keyId = options.keyId;
    this.#apiEndpoint = options.apiEndpoint ?? KMS_API_BASE;
    this.#auth = options.auth;
  }

  async encrypt(
    plaintext: string,
    aad: string,
    _context: YdbEncryptionContext,
  ): Promise<Uint8Array> {
    const token = await this.#auth.getToken(YCLOUD_AUTH_USAGE);

    const body: Record<string, string> = {
      plaintext: Buffer.from(plaintext, 'utf8').toString('base64'),
    };

    if (aad) {
      body.aadContext = Buffer.from(aad, 'utf8').toString('base64');
    }

    const url = `${this.#apiEndpoint}/kms/v1/keys/${this.#keyId}:encrypt`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`KMS encrypt failed: ${response.status} ${text}`);
    }

    const data = (await response.json()) as KmsEncryptResponse;
    return new Uint8Array(Buffer.from(data.ciphertext, 'base64'));
  }

  async decrypt(
    ciphertext: Uint8Array,
    aad: string,
    _context: YdbEncryptionContext,
  ): Promise<string> {
    const token = await this.#auth.getToken(YCLOUD_AUTH_USAGE);

    const body: Record<string, string> = {
      ciphertext: Buffer.from(ciphertext).toString('base64'),
    };

    if (aad) {
      body.aadContext = Buffer.from(aad, 'utf8').toString('base64');
    }

    const url = `${this.#apiEndpoint}/kms/v1/keys/${this.#keyId}:decrypt`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`KMS decrypt failed: ${response.status} ${text}`);
    }

    const data = (await response.json()) as KmsDecryptResponse;
    return Buffer.from(data.plaintext, 'base64').toString('utf8');
  }
}
