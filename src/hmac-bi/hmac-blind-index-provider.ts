import { createHmac } from 'node:crypto';
import type {
  YdbBlindIndexProvider,
  YdbEncryptionContext,
} from '@ycforge/ydb-orm';

export interface KmsBlindIndexProviderOptions {
  /**
   * Ключ для HMAC-SHA256 (canonical padded Base64, минимум 32 байта
   * после декодирования).
   *
   * Строка строго валидируется: недопустимые символы, некорректный
   * паддинг и не-canonical хвостовые биты отвергаются (например,
   * вывод `openssl rand -base64 32` подходит, а «похожие на base64»
   * произвольные строки — нет).
   *
   * Yandex KMS не предоставляет нативной хеш-функции, поэтому для
   * blind index используется HMAC-SHA256 с отдельным ключом.
   */
  blindIndexKey: string;
}

const BASE64_ALPHABET_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Строгое декодирование Base64: алфавит, корректный паддинг и
 * каноничность (перекодирование обязано воспроизвести вход 1:1 —
 * отсекает «мусорные» хвостовые биты и лишний/неправильный паддинг,
 * которые lenient-декодер Node молча игнорирует).
 *
 * Пробелы по краям допускаются (удобно для значений из env).
 */
function decodeCanonicalBase64(input: string): Buffer {
  const normalized = input.trim();

  if (
    !BASE64_ALPHABET_RE.test(normalized) ||
    normalized.length % 4 === 1 // длина, невозможная для валидного Base64
  ) {
    throw new Error(
      'blindIndexKey must be a valid canonical Base64 string (as produced by e.g. `openssl rand -base64 32`)',
    );
  }

  const decoded = Buffer.from(normalized, 'base64');
  if (decoded.toString('base64') !== normalized) {
    throw new Error(
      'blindIndexKey must be a valid canonical Base64 string (as produced by e.g. `openssl rand -base64 32`)',
    );
  }

  return decoded;
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

    this.#key = decodeCanonicalBase64(options.blindIndexKey);

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
