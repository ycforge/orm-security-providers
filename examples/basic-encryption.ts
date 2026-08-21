/**
 * Basic encryption / decryption with Yandex Cloud KMS.
 *
 * Контракт @ycforge/ydb-orm v0.2+: encrypt() возвращает raw ciphertext
 * (Uint8Array), decrypt() принимает Uint8Array и возвращает строку.
 * Base64 используется только внутри KMS REST API.
 *
 * Run:
 *   KMS_KEY_ID=aby... KMS_AUTH_TYPE=iam_token KMS_IAM_TOKEN=... npx tsx examples/basic-encryption.ts
 */
import { KmsEncryptionProvider } from '../src/yandex-kms/kms-encryption-provider.js';
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
console.log('ciphertext:', ciphertext); // Uint8Array — так значение хранится в колонке Bytes
console.log('ciphertext bytes:', ciphertext.length);

const decrypted = await provider.decrypt(ciphertext, '', context);
console.log('decrypted:', decrypted);
console.log('match:', plaintext === decrypted);
