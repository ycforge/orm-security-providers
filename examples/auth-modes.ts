/**
 * Three authentication modes for KMS access.
 */
import {
  KmsEncryptionProvider,
  type KmsEncryptionProviderOptions,
} from '../src/kms-encryption-provider.js';

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
const iamToken: KmsEncryptionProviderOptions = {
  keyId: process.env.KMS_KEY_ID!,
  auth_type: 'iam_token',
  authOptions: { iam_token: process.env.KMS_IAM_TOKEN! },
};

// pick one based on environment
const options = process.env.KMS_AUTH_TYPE === 'auth_key'
  ? authKey
  : process.env.KMS_AUTH_TYPE === 'meta'
    ? meta
    : iamToken;

const provider = new KmsEncryptionProvider(options);
console.log('provider created with auth_type:', options.auth_type);
