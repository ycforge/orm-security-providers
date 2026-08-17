/**
 * Basic encryption / decryption with Yandex Cloud KMS.
 *
 * Run:
 *   KMS_KEY_ID=aby... KMS_AUTH_TYPE=iam_token KMS_IAM_TOKEN=... npx tsx examples/basic-encryption.ts
 */
import { KmsEncryptionProvider } from '../src/kms-encryption-provider.js';
import type { YdbEncryptionContext } from '@ycforge/ydb-orm';

const provider = new KmsEncryptionProvider({
  keyId: process.env.KMS_KEY_ID!,
  auth_type: 'iam_token',
  authOptions: { iam_token: process.env.KMS_IAM_TOKEN! },
});

const context: YdbEncryptionContext = {
  entityName: 'User',
  tableName: 'users',
  fieldName: 'email',
  primaryKeyValue: '1',
  aadFields: {},
};

const plaintext = 'alice@example.com';

const ciphertext = await provider.encrypt(plaintext, '', context);
console.log('ciphertext:', ciphertext);

const decrypted = await provider.decrypt(ciphertext, '', context);
console.log('decrypted:', decrypted);
console.log('match:', plaintext === decrypted);
