import { createHmac } from 'node:crypto';
import type {
  YdbBlindIndexProvider,
  YdbEncryptionContext,
} from '@ycforge/ydb-orm';

export interface KmsBlindIndexProviderOptions {
  /**
   * Ключ для HMAC-SHA256 (base64-encoded, минимум 32 байта).
   *
   * Yandex KMS не предоставляет нативной хеш-функции, поэтому для
   * blind index используется HMAC-SHA256 с отдельным ключом.
   */
  blindIndexKey: string;
}

/**
 * Провайдер blind index для @ycforge/ydb-orm.
 *
 * Yandex KMS не предоставляет детерминированной хеш-функции,
 * поэтому хеш index реализован через HMAC-SHA256 с отдельным ключом.
 * Рекомендуется хранить ключ в переменных окружения.
 *
 * ```ts
 * blindIndexProvider: new KmsBlindIndexProvider({
 *   blindIndexKey: process.env.KMS_BI_KEY!,
 * }),
 * ```
 */
export class KmsBlindIndexProvider implements YdbBlindIndexProvider {
  readonly #key: Buffer;

  constructor(options: KmsBlindIndexProviderOptions) {
    if (!options.blindIndexKey) {
      throw new Error('blindIndexKey is required');
    }

    this.#key = Buffer.from(options.blindIndexKey, 'base64');

    if (this.#key.length < 32) {
      throw new Error(
        'blindIndexKey must be at least 32 bytes (256 bits) when decoded',
      );
    }
  }

  hash(plaintext: string, _context: YdbEncryptionContext): Promise<string> {
    return Promise.resolve(
      createHmac('sha256', this.#key).update(plaintext).digest('base64'),
    );
  }
}
