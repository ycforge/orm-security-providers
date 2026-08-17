import { jest } from '@jest/globals';
import { KmsEncryptionProvider } from '../yandex-kms/kms-encryption-provider.js';
import type { YdbEncryptionContext } from '@ycforge/ydb-orm';

const originalFetch = globalThis.fetch;

const defaultContext: YdbEncryptionContext = {
  entityName: 'UserEntity',
  tableName: 'users',
  fieldName: 'email',
  primaryKeyValue: 'uuid-123',
  aadFields: { organization: 'Acme' },
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

describe('KmsEncryptionProvider', () => {
  const baseOpts = {
    keyId: 'aby123key',
    auth_type: 'iam_token' as const,
    authOptions: { iam_token: 'test-token' },
  };

  describe('constructor', () => {
    it('creates provider with required options', () => {
      const provider = new KmsEncryptionProvider(baseOpts);
      expect(provider).toBeDefined();
    });

    it('throws when keyId is empty', () => {
      expect(
        () =>
          new KmsEncryptionProvider({
            ...baseOpts,
            keyId: '',
          }),
      ).toThrow('keyId is required');
    });

    it('uses custom apiEndpoint', () => {
      const provider = new KmsEncryptionProvider({
        ...baseOpts,
        apiEndpoint: 'https://custom-kms.example.com',
      });
      expect(provider).toBeDefined();
    });
  });

  describe('encrypt', () => {
    it('calls KMS encrypt API with base64-encoded plaintext', async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: 'aby123key',
            versionId: 'v1',
            ciphertext: 'base64-ciphertext',
          }),
        ),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);
      const result = await provider.encrypt(
        'hello world',
        '',
        defaultContext,
      );

      expect(result).toBe('base64-ciphertext');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        'https://kms.yandex/kms/v1/keys/aby123key:encrypt',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer test-token',
          },
        }),
      );

      const body = JSON.parse(
        (globalThis.fetch as jest.Mock).mock.calls[0][1].body,
      );
      expect(body.plaintext).toBe(
        Buffer.from('hello world', 'utf8').toString('base64'),
      );
      expect(body.aadContext).toBeUndefined();
    });

    it('includes aadContext when AAD is provided', async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: 'aby123key',
            versionId: 'v1',
            ciphertext: 'enc-with-aad',
          }),
        ),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);
      const result = await provider.encrypt(
        'secret',
        'org=Acme',
        defaultContext,
      );

      expect(result).toBe('enc-with-aad');

      const body = JSON.parse(
        (globalThis.fetch as jest.Mock).mock.calls[0][1].body,
      );
      expect(body.aadContext).toBe(
        Buffer.from('org=Acme', 'utf8').toString('base64'),
      );
    });

    it('throws on non-200 response', async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(errorResponse(403, 'Permission denied')),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);

      await expect(
        provider.encrypt('data', '', defaultContext),
      ).rejects.toThrow('KMS encrypt failed: 403');
    });

    it('uses iam_token auth by default', async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: 'aby123key',
            versionId: 'v1',
            ciphertext: 'result',
          }),
        ),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);
      await provider.encrypt('x', '', defaultContext);

      const init = (globalThis.fetch as jest.Mock).mock.calls[0][1];
      expect(init.headers.Authorization).toBe('Bearer test-token');
    });
  });

  describe('decrypt', () => {
    it('calls KMS decrypt API with ciphertext', async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: 'aby123key',
            versionId: 'v1',
            plaintext: Buffer.from('hello world', 'utf8').toString('base64'),
          }),
        ),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);
      const result = await provider.decrypt(
        'base64-ciphertext',
        '',
        defaultContext,
      );

      expect(result).toBe('hello world');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        'https://kms.yandex/kms/v1/keys/aby123key:decrypt',
        expect.objectContaining({ method: 'POST' }),
      );

      const body = JSON.parse(
        (globalThis.fetch as jest.Mock).mock.calls[0][1].body,
      );
      expect(body.ciphertext).toBe('base64-ciphertext');
      expect(body.aadContext).toBeUndefined();
    });

    it('includes aadContext when AAD is provided', async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: 'aby123key',
            versionId: 'v1',
            plaintext: Buffer.from('decrypted', 'utf8').toString('base64'),
          }),
        ),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);
      await provider.decrypt('cipher', 'org=Acme', defaultContext);

      const body = JSON.parse(
        (globalThis.fetch as jest.Mock).mock.calls[0][1].body,
      );
      expect(body.aadContext).toBe(
        Buffer.from('org=Acme', 'utf8').toString('base64'),
      );
    });

    it('throws on non-200 response', async () => {
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(errorResponse(400, 'Invalid ciphertext')),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);

      await expect(
        provider.decrypt('bad', '', defaultContext),
      ).rejects.toThrow('KMS decrypt failed: 400');
    });

    it('handles UTF-8 characters correctly', async () => {
      const utf8Text = 'Привет мир 🌍';
      globalThis.fetch = jest.fn(() =>
        Promise.resolve(
          jsonResponse({
            keyId: 'aby123key',
            versionId: 'v1',
            plaintext: Buffer.from(utf8Text, 'utf8').toString('base64'),
          }),
        ),
      ) as any;

      const provider = new KmsEncryptionProvider(baseOpts);
      const result = await provider.decrypt('cipher', '', defaultContext);

      expect(result).toBe(utf8Text);
    });
  });

  describe('encrypt → decrypt roundtrip', () => {
    it('preserves data through base64 encoding', async () => {
      let capturedBody: any;

      globalThis.fetch = jest.fn((url: string, init: any) => {
        const body = JSON.parse(init.body);

        if (String(url).includes(':encrypt')) {
          capturedBody = body;
          return Promise.resolve(
            jsonResponse({
              keyId: 'aby123key',
              versionId: 'v1',
              ciphertext: body.plaintext,
            }),
          );
        }

        return Promise.resolve(
          jsonResponse({
            keyId: 'aby123key',
            versionId: 'v1',
            plaintext: body.ciphertext,
          }),
        );
      }) as any;

      const provider = new KmsEncryptionProvider(baseOpts);

      const encrypted = await provider.encrypt(
        'test data',
        'aad-value',
        defaultContext,
      );
      const decrypted = await provider.decrypt(
        encrypted,
        'aad-value',
        defaultContext,
      );

      expect(decrypted).toBe('test data');
    });
  });
});
