/**
 * Three authentication modes for KMS access.
 */
import {
  KmsEncryptionProvider,
  type KmsEncryptionProviderOptions,
} from '../src/yandex-kms/kms-encryption-provider.js';

// ── 1. Service-account key (recommended for local / CI) ──────────
const authKey: KmsEncryptionProviderOptions = {
  keyId: process.env.KMS_KEY_ID!,
  auth_type: 'auth_key',
  authOptions: {
    authorized_key_path: './authorized_key.json',
  },
};

// ── 2. VM metadata (production inside Yandex Cloud) ──────────────
const meta: KmsEncryptionProviderOptions = {
  keyId: process.env.KMS_KEY_ID!,
  auth_type: 'meta',
  authOptions: {},
};

// ── 3. Static IAM token (quick test) ─────────────────────────────
// Non-refreshing: the token is served as-is and the server decides
// validity. Optionally declare its expiry — after that moment
// getToken() throws instead of sending a dead token.
const iamToken: KmsEncryptionProviderOptions = {
  keyId: process.env.KMS_KEY_ID!,
  auth_type: 'iam_token',
  authOptions: {
    iam_token: process.env.KMS_IAM_TOKEN!,
    ...(process.env.KMS_IAM_TOKEN_EXPIRES_AT
      ? { iam_token_expires_at: process.env.KMS_IAM_TOKEN_EXPIRES_AT }
      : {}),
  },
};

// pick one based on environment
const options = process.env.KMS_AUTH_TYPE === 'auth_key'
  ? authKey
  : process.env.KMS_AUTH_TYPE === 'meta'
    ? meta
    : iamToken;

const provider = new KmsEncryptionProvider(options);
console.log('provider created with auth_type:', options.auth_type);
