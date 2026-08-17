import { KmsBlindIndexProvider } from '../hmac-bi/hmac-blind-index-provider.js';
import type { YdbEncryptionContext } from '@ycforge/ydb-orm';

const defaultContext: YdbEncryptionContext = {
  entityName: 'UserEntity',
  tableName: 'users',
  fieldName: 'email',
  primaryKeyValue: 'uuid-123',
  aadFields: {},
};

describe('KmsBlindIndexProvider', () => {
  describe('constructor', () => {
    it('creates provider with valid base64 key', () => {
      const key = Buffer.alloc(32).toString('base64');
      const provider = new KmsBlindIndexProvider({ blindIndexKey: key });
      expect(provider).toBeDefined();
    });

    it('throws when blindIndexKey is empty', () => {
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: '' }),
      ).toThrow('blindIndexKey is required');
    });

    it('throws when key is shorter than 32 bytes', () => {
      const shortKey = Buffer.alloc(16).toString('base64');
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: shortKey }),
      ).toThrow('at least 32 bytes');
    });

    it('accepts exactly 32-byte key', () => {
      const key = Buffer.alloc(32).toString('base64');
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: key }),
      ).not.toThrow();
    });

    it('accepts longer keys', () => {
      const key = Buffer.alloc(64).toString('base64');
      expect(
        () => new KmsBlindIndexProvider({ blindIndexKey: key }),
      ).not.toThrow();
    });
  });

  describe('hash', () => {
    const key = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8').toString(
      'base64',
    );
    const provider = new KmsBlindIndexProvider({ blindIndexKey: key });

    it('returns a base64-encoded HMAC-SHA256 hash', async () => {
      const hash = await provider.hash('test@example.com', defaultContext);

      expect(typeof hash).toBe('string');
      expect(hash.length).toBeGreaterThan(0);
      // base64 of 32 bytes = 44 chars
      expect(hash.length).toBe(44);
    });

    it('is deterministic: same input produces same output', async () => {
      const h1 = await provider.hash('test@example.com', defaultContext);
      const h2 = await provider.hash('test@example.com', defaultContext);

      expect(h1).toBe(h2);
    });

    it('produces different hashes for different inputs', async () => {
      const h1 = await provider.hash('alice@example.com', defaultContext);
      const h2 = await provider.hash('bob@example.com', defaultContext);

      expect(h1).not.toBe(h2);
    });

    it('ignores context parameter', async () => {
      const ctx1: YdbEncryptionContext = {
        entityName: 'UserEntity',
        tableName: 'users',
        fieldName: 'email',
        primaryKeyValue: 'uuid-1',
        aadFields: {},
      };
      const ctx2: YdbEncryptionContext = {
        entityName: 'AdminEntity',
        tableName: 'admins',
        fieldName: 'login',
        primaryKeyValue: 'uuid-2',
        aadFields: { role: 'admin' },
      };

      const h1 = await provider.hash('same-value', ctx1);
      const h2 = await provider.hash('same-value', ctx2);

      expect(h1).toBe(h2);
    });

    it('produces different hashes with different keys', async () => {
      const key2 = Buffer.from(
        'abcdef0123456789abcdef0123456789',
        'utf8',
      ).toString('base64');
      const provider2 = new KmsBlindIndexProvider({ blindIndexKey: key2 });

      const h1 = await provider.hash('same', defaultContext);
      const h2 = await provider2.hash('same', defaultContext);

      expect(h1).not.toBe(h2);
    });

    it('handles empty string input', async () => {
      const hash = await provider.hash('', defaultContext);
      expect(typeof hash).toBe('string');
      expect(hash.length).toBe(44);
    });

    it('handles Unicode input', async () => {
      const hash = await provider.hash('Привет 🌍', defaultContext);
      expect(typeof hash).toBe('string');
      expect(hash.length).toBe(44);
    });
  });
});
