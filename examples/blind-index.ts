/**
 * Blind index — deterministic HMAC-SHA256 for searchable encryption.
 *
 * Generate a key:
 *   openssl rand -base64 32
 *
 * Run:
 *   KMS_BLIND_INDEX_KEY=<base64> npx tsx examples/blind-index.ts
 */
import { KmsBlindIndexProvider } from '../src/hmac-bi/hmac-blind-index-provider.js';
import type { YdbEncryptionContext } from '@ycforge/ydb-orm';

const provider = new KmsBlindIndexProvider({
  blindIndexKey: process.env.KMS_BLIND_INDEX_KEY!,
});

const context: YdbEncryptionContext = {
  entityName: 'User',
  tableName: 'users',
  fieldName: 'email',
  primaryKeyValue: '1',
  aadFields: {},
};

const email = 'alice@example.com';

const hash = await provider.hash(email, context);
console.log('hash:', hash);
console.log('length:', hash.length); // 44 (base64 SHA-256)

// deterministic
const hash2 = await provider.hash(email, context);
console.log('deterministic:', hash === hash2); // true

// different input → different hash
const hash3 = await provider.hash('bob@example.com', context);
console.log('unique:', hash !== hash3); // true
