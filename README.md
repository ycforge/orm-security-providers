# @ycforge/orm-security-providers

Encryption & blind-index providers for [@ycforge/ydb-orm](https://github.com/ycforge/ydb-orm).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](nodejs.org)
[![npm](https://img.shields.io/npm/v/@ycforge/orm-security-providers.svg)](https://www.npmjs.com/package/@ycforge/orm-security-providers)

## Install

```bash
npm install @ycforge/orm-security-providers @ycforge/ydb-orm
# or
yarn add @ycforge/orm-security-providers @ycforge/ydb-orm
```

## Providers

| Subpath | Exports | Description |
|---------|---------|-------------|
| `@ycforge/orm-security-providers/yandex-kms` | `KmsEncryptionProvider`, `IamTokenManager` | Encrypt / decrypt via Yandex Cloud KMS SymmetricCrypto REST API |
| `@ycforge/orm-security-providers/hmac-bi` | `KmsBlindIndexProvider` | Deterministic HMAC-SHA256 blind indexes |

Import from the specific subpath:

```ts
import { KmsEncryptionProvider } from '@ycforge/orm-security-providers/yandex-kms';
import { KmsBlindIndexProvider } from '@ycforge/orm-security-providers/hmac-bi';
```

Or from the root (re-exports everything):

```ts
import { KmsEncryptionProvider, KmsBlindIndexProvider } from '@ycforge/orm-security-providers';
```

## Quick Start

```ts
import { Module } from '@nestjs/common';
import { YdbOrmModule } from '@ycforge/ydb-orm';
import { KmsEncryptionProvider } from '@ycforge/orm-security-providers/yandex-kms';
import { KmsBlindIndexProvider } from '@ycforge/orm-security-providers/hmac-bi';

@Module({
  imports: [
    YdbOrmModule.forRoot({
      encryption: new KmsEncryptionProvider({
        keyId: process.env.KMS_KEY_ID!,
        auth_type: 'auth_key',
        authOptions: {
          authorized_key_path: './authorized_key.json',
        },
      }),
      blindIndex: new KmsBlindIndexProvider({
        blindIndexKey: process.env.KMS_BLIND_INDEX_KEY!,
      }),
    }),
  ],
})
export class AppModule {}
```

## `@ycforge/orm-security-providers/yandex-kms`

### KmsEncryptionProvider

```ts
new KmsEncryptionProvider(options: KmsEncryptionProviderOptions)
```

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `keyId` | `string` | yes | — | KMS symmetric key ID |
| `auth_type` | `'meta' \| 'auth_key' \| 'iam_token'` | yes | — | Auth method |
| `authOptions` | `KmsAuthOptions` | yes | — | Auth parameters |
| `apiEndpoint` | `string` | no | `https://kms.yandex` | KMS API base URL |

Methods:

```ts
encrypt(plaintext: string, aad: string, context: YdbEncryptionContext): Promise<string>
decrypt(ciphertext: string, aad: string, context: YdbEncryptionContext): Promise<string>
```

### Authentication

| Mode | Description | Required options |
|------|-------------|-----------------|
| `meta` | VM metadata service (works only inside Yandex Cloud VMs) | none |
| `auth_key` | Service-account JSON key → JWT → IAM token exchange | `authorized_key_path` |
| `iam_token` | Static IAM token (no auto-refresh) | `iam_token` |

#### auth_key (recommended for local / CI)

```bash
yc iam service-account create --name kms-encrypter
yc iam key create --service-account-id <sa_id> --output authorized_key.json
yc kms symmetric-key add-access-binding \
  --id <key_id> \
  --service-account-id <sa_id> \
  --role kms.keys.encrypterDecrypter
```

```ts
new KmsEncryptionProvider({
  keyId: 'aby...',
  auth_type: 'auth_key',
  authOptions: { authorized_key_path: './authorized_key.json' },
});
```

#### meta (production on VM)

```ts
new KmsEncryptionProvider({
  keyId: 'aby...',
  auth_type: 'meta',
  authOptions: {},
});
```

#### iam_token (quick test)

```bash
yc iam create-token
```

```ts
new KmsEncryptionProvider({
  keyId: 'aby...',
  auth_type: 'iam_token',
  authOptions: { iam_token: '<token>' },
});
```

### IamTokenManager

```ts
import { IamTokenManager } from '@ycforge/orm-security-providers/yandex-kms';

const manager = new IamTokenManager('auth_key', {
  authorized_key_path: './authorized_key.json',
});
const token = await manager.getToken();
```

## `@ycforge/orm-security-providers/hmac-bi`

### KmsBlindIndexProvider

```ts
new KmsBlindIndexProvider(options: KmsBlindIndexProviderOptions)
```

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `blindIndexKey` | `string` | yes | Base64-encoded HMAC key (>= 32 bytes) |

Method:

```ts
hash(plaintext: string, context: YdbEncryptionContext): Promise<string>
```

Returns deterministic base64 HMAC-SHA256 (44 characters). Context is accepted but ignored — the hash depends only on the key and value.

Generate a key:

```bash
openssl rand -base64 32
```

## Usage with ydb-orm entities

```ts
import { Entity, PrimaryKey, Field, YdbEncrypted, YdbBlindIndex } from '@ycforge/ydb-orm';

@Entity('users')
class User {
  @PrimaryKey()
  id: string = '';

  @Field()
  @YdbEncrypted()
  email: string = '';

  @Field()
  @YdbBlindIndex()
  @YdbEncrypted({ aadFields: ['orgId'] })
  ssn: string = '';

  @Field()
  orgId: string = '';
}
```

## Testing

```bash
yarn test              # unit tests
yarn test:integration  # real KMS API (requires .env)
yarn test:cov          # coverage
```

## Project Structure

```
src/
  index.ts                              # root barrel — re-exports all providers
  yandex-kms/
    index.ts                            # barrel for KMS + IAM
    kms-encryption-provider.ts          # encrypt / decrypt via KMS REST API
    iam-token-manager.ts                # IAM token management (3 auth modes)
  hmac-bi/
    index.ts                            # barrel for HMAC blind index
    hmac-blind-index-provider.ts        # HMAC-SHA256 blind index
  __tests__/
    setup.ts                            # dotenv loader for Jest
    helpers.ts                          # test config from env
    kms-encryption-provider.spec.ts
    kms-blind-index-provider.spec.ts
    iam-token-manager.spec.ts
    e2e.spec.ts
    integration.spec.ts
```

## License

MIT © [ycforge](https://github.com/ycforge)
