import { jest } from '@jest/globals';
import { randomBytes } from 'node:crypto';
import { createAuth } from '@ycforge/auth';
import { KmsEncryptionProvider } from '../yandex-kms/kms-encryption-provider.js';
import { KmsBlindIndexProvider } from '../hmac-bi/hmac-blind-index-provider.js';
import type { YdbEncryptionContext } from '@ycforge/ydb-orm';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.clearAllMocks();
});

/** Фабрика mock-провайдера KMS с подменённым fetch (base64 — только внутри адаптера). */
function createMockKmsProviders() {
  const keyId = 'test-key-id';
  // base64(ciphertext) → base64(plaintext)
  const vault = new Map<string, string>();

  const encProvider = new KmsEncryptionProvider({
    keyId,
    auth: createAuth({ type: 'iam_token', token: 'test-token' }),
  });

  const biProvider = new KmsBlindIndexProvider({
    blindIndexKey: Buffer.alloc(32).toString('base64'),
  });

  const kmsResponse = (data: unknown, status = 200): Promise<Response> =>
    Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(data),
      text: () => Promise.resolve(JSON.stringify(data)),
    } as Response);

  const mockFetch = jest.fn(
    (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const body = JSON.parse(init!.body as string);
      const urlText =
        typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;

      if (urlText.includes(':encrypt')) {
        const ciphertext = randomBytes(48).toString('base64');
        vault.set(ciphertext, body.plaintext);
        return kmsResponse({ keyId, versionId: 'v1', ciphertext });
      }

      if (urlText.includes(':decrypt')) {
        return kmsResponse({
          keyId,
          versionId: 'v1',
          plaintext: vault.get(body.ciphertext)!,
        });
      }

      return kmsResponse({}, 404);
    },
  );

  return { encProvider, biProvider, mockFetch };
}

const context: YdbEncryptionContext = {
  entityName: 'UserEntity',
  tableName: 'users',
  fieldName: 'email',
  primaryKeyValue: 'uuid-abc',
  aadFields: { organization: 'Acme Corp' },
};

describe('E2E: KMS encrypt → decrypt roundtrip (mocked)', () => {
  it('full cycle: encrypt → decrypt returns original plaintext', async () => {
    const { encProvider, mockFetch } = createMockKmsProviders();
    globalThis.fetch = mockFetch;

    const plaintext = 'user@example.com';
    const aad = 'organization=Acme Corp';

    const ciphertext: Uint8Array = await encProvider.encrypt(
      plaintext,
      aad,
      context,
    );
    expect(ciphertext).toBeInstanceOf(Uint8Array);

    const decrypted = await encProvider.decrypt(ciphertext, aad, context);

    expect(decrypted).toBe(plaintext);
  });

  it('full cycle: encrypt → blind index → search', async () => {
    const { encProvider, biProvider, mockFetch } = createMockKmsProviders();
    globalThis.fetch = mockFetch;

    const plaintext = 'search@example.com';
    const aad = 'organization=Acme Corp';

    const ciphertext = await encProvider.encrypt(plaintext, aad, context);
    const blindIndex = await biProvider.hash(plaintext, context);

    expect(ciphertext).not.toBeNull();
    expect(blindIndex).not.toBe(plaintext);

    const decrypted = await encProvider.decrypt(ciphertext, aad, context);
    expect(decrypted).toBe(plaintext);
  });

  it('different AAD produces different ciphertext', async () => {
    const { encProvider } = createMockKmsProviders();

    // Override mock: ciphertext зависит от AAD
    const vault = new Map<string, string>();
    globalThis.fetch = jest.fn(
      (_url: string | URL | Request, init?: RequestInit) => {
        const body = JSON.parse(init!.body as string);
        const aadSeed = Buffer.from(body.aadContext ?? '', 'base64');
        const ciphertext = Buffer.from(
          Array.from(
            { length: 48 },
            (_, i) =>
              (i * 53 + 7 + (aadSeed[i % Math.max(aadSeed.length, 1)] ?? 0)) %
              256,
          ),
        ).toString('base64');
        vault.set(ciphertext, body.plaintext);
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () =>
            Promise.resolve({
              keyId: 'test-key-id',
              versionId: 'v1',
              ciphertext,
            }),
          text: () => Promise.resolve(''),
        } as Response);
      },
    );

    const c1 = await encProvider.encrypt('same@email.com', 'org=Acme', context);
    const c2 = await encProvider.encrypt(
      'same@email.com',
      'org=Other',
      context,
    );

    expect(Buffer.compare(Buffer.from(c1), Buffer.from(c2))).not.toBe(0);
  });

  it('handles multiple fields with different contexts', async () => {
    const { encProvider, mockFetch } = createMockKmsProviders();
    globalThis.fetch = mockFetch;

    const emailCtx: YdbEncryptionContext = {
      entityName: 'UserEntity',
      tableName: 'users',
      fieldName: 'email',
      aadFields: {},
    };
    const phoneCtx: YdbEncryptionContext = {
      entityName: 'UserEntity',
      tableName: 'users',
      fieldName: 'phone',
      aadFields: {},
    };

    const email = await encProvider.encrypt('user@test.com', '', emailCtx);
    const phone = await encProvider.encrypt('+7-999-123-4567', '', phoneCtx);

    const emailDec = await encProvider.decrypt(email, '', emailCtx);
    const phoneDec = await encProvider.decrypt(phone, '', phoneCtx);

    expect(emailDec).toBe('user@test.com');
    expect(phoneDec).toBe('+7-999-123-4567');
  });

  it('blind index is consistent across multiple calls', async () => {
    const { biProvider } = createMockKmsProviders();

    for (const value of ['a@b.com', 'c@d.com', '', 'Привет']) {
      const h1 = await biProvider.hash(value, context);
      const h2 = await biProvider.hash(value, context);
      expect(h1).toBe(h2);
    }
  });

  it('KMS API errors propagate correctly', async () => {
    const { encProvider } = createMockKmsProviders();

    globalThis.fetch = jest.fn(() =>
      Promise.resolve({
        ok: false,
        status: 400,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve('Bad request'),
      } as Response),
    );

    await expect(encProvider.encrypt('data', '', context)).rejects.toThrow(
      'KMS encrypt failed: 400',
    );

    await expect(
      encProvider.decrypt(new Uint8Array([1]), '', context),
    ).rejects.toThrow('KMS decrypt failed: 400');
  });
});
