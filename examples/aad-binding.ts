/**
 * AAD (Additional Authenticated Data) — binds ciphertext to specific field values.
 *
 * When encrypted with AAD, decryption with a different AAD will fail.
 * Use @YdbSecurityAAD fields in ydb-orm entities.
 */
import { createAuth } from '@ycforge/auth';
import { KmsEncryptionProvider } from '../src/yandex-kms/kms-encryption-provider.js';
import type { YdbEncryptionContext } from '@ycforge/ydb-orm';

const provider = new KmsEncryptionProvider({
  keyId: process.env.KMS_KEY_ID!,
  auth: createAuth({ type: 'iam_token', token: process.env.KMS_IAM_TOKEN! }),
});

const context: YdbEncryptionContext = {
  entityName: 'User',
  tableName: 'users',
  fieldName: 'ssn',
  primaryKeyValue: '1',
  aadFields: {},
};

const plaintext = '123-45-6789';
const correctAad = 'orgId=org-123';
const wrongAad = 'orgId=org-999';

// encrypt with AAD
const ciphertext = await provider.encrypt(plaintext, correctAad, context);
console.log('ciphertext bytes:', ciphertext.length); // Uint8Array

// decrypt with correct AAD — works
const decrypted = await provider.decrypt(ciphertext, correctAad, context);
console.log('correct AAD:', decrypted === plaintext); // true

// decrypt with wrong AAD — throws
try {
  await provider.decrypt(ciphertext, wrongAad, context);
  console.log('should not reach here');
} catch (err) {
  console.log('wrong AAD rejected:', (err as Error).message);
}
