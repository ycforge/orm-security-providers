import { afterEach, describe, it, expect, jest } from '@jest/globals';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { createAuth } from '@ycforge/auth';
import type { YdbEncryptionContext } from '@ycforge/ydb-orm';
import { KmsEncryptionProvider } from '../yandex-kms/kms-encryption-provider.js';
import { KmsBlindIndexProvider } from '../hmac-bi/hmac-blind-index-provider.js';

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});
const context: YdbEncryptionContext = {
  entityName: 'User',
  tableName: 'users',
  fieldName: 'email',
  primaryKeyValue: '["pk:v1",[["tenant","Utf8","one"],["id","Utf8","two"]]]',
  aadFields: {},
};
const options = {
  keyId: 'test-key',
  auth: createAuth({ type: 'iam_token', token: 'test-only' }),
};
function authenticatedKmsMock() {
  const key = randomBytes(32);
  globalThis.fetch = jest.fn(
    async (_url: string | URL | Request, request?: RequestInit) => {
      await Promise.resolve();
      const body = JSON.parse(request?.body as string) as Record<
        string,
        string
      >;
      const aad = Buffer.from(body.aadContext, 'base64');
      try {
        if (body.plaintext !== undefined) {
          const iv = randomBytes(12);
          const cipher = createCipheriv('aes-256-gcm', key, iv);
          cipher.setAAD(aad);
          const ciphertext = Buffer.concat([
            cipher.update(Buffer.from(body.plaintext, 'base64')),
            cipher.final(),
          ]);
          return Response.json({
            ciphertext: Buffer.concat([
              iv,
              cipher.getAuthTag(),
              ciphertext,
            ]).toString('base64'),
          });
        }
        const bytes = Buffer.from(body.ciphertext, 'base64');
        const decipher = createDecipheriv(
          'aes-256-gcm',
          key,
          bytes.subarray(0, 12),
        );
        decipher.setAAD(aad);
        decipher.setAuthTag(bytes.subarray(12, 28));
        const plaintext = Buffer.concat([
          decipher.update(bytes.subarray(28)),
          decipher.final(),
        ]);
        return Response.json({ plaintext: plaintext.toString('base64') });
      } catch {
        return new Response('authentication failed', { status: 400 });
      }
    },
  );
}

describe('authenticated table/field/record domains', () => {
  it.each(['tableName', 'fieldName', 'primaryKeyValue'] as const)(
    'rejects ciphertext moved to another %s even without explicit AAD',
    async (property) => {
      authenticatedKmsMock();
      const provider = new KmsEncryptionProvider(options);
      const ciphertext = await provider.encrypt('secret', '', context);
      await expect(provider.decrypt(ciphertext, '', context)).resolves.toBe(
        'secret',
      );
      await expect(
        provider.decrypt(ciphertext, '', { ...context, [property]: 'other' }),
      ).rejects.toThrow('KMS decrypt failed: 400');
    },
  );

  it('authenticates explicit AAD and the application/database domain', async () => {
    authenticatedKmsMock();
    const one = new KmsEncryptionProvider({
      ...options,
      domain: 'database-one',
    });
    const two = new KmsEncryptionProvider({
      ...options,
      domain: 'database-two',
    });
    const ciphertext = await one.encrypt('secret', 'custom-aad', context);
    await expect(one.decrypt(ciphertext, 'wrong-aad', context)).rejects.toThrow(
      '400',
    );
    await expect(
      two.decrypt(ciphertext, 'custom-aad', context),
    ).rejects.toThrow('400');
    await expect(
      one.decrypt(ciphertext, 'custom-aad', {
        ...context,
        entityName: 'RenamedClass',
      }),
    ).resolves.toBe('secret');
  });

  it.each(['tableName', 'fieldName', 'primaryKeyValue'] as const)(
    'fails closed before network if %s is missing',
    async (property) => {
      authenticatedKmsMock();
      const provider = new KmsEncryptionProvider(options);
      await expect(
        provider.encrypt('secret', '', {
          ...context,
          [property]: undefined,
        }),
      ).rejects.toThrow(`context.${property}`);
      expect(globalThis.fetch).not.toHaveBeenCalled();
    },
  );

  it('separates blind indexes by table, field and application while allowing PK-independent searches', async () => {
    const key = randomBytes(32).toString('base64');
    const one = new KmsBlindIndexProvider({
      blindIndexKey: key,
      domain: 'one',
    });
    const two = new KmsBlindIndexProvider({
      blindIndexKey: key,
      domain: 'two',
    });
    const index = await one.hash('same', context);
    await expect(
      one.hash('same', {
        ...context,
        primaryKeyValue: undefined,
        entityName: 'Renamed',
      }),
    ).resolves.toBe(index);
    for (const property of ['tableName', 'fieldName'] as const) {
      expect(
        await one.hash('same', { ...context, [property]: 'other' }),
      ).not.toBe(index);
    }
    expect(await two.hash('same', context)).not.toBe(index);
    expect(
      await one.hash('same', { ...context, tableName: 'a:b', fieldName: 'c' }),
    ).not.toBe(
      await one.hash('same', { ...context, tableName: 'a', fieldName: 'b:c' }),
    );
  });
});
