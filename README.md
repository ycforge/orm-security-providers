# @ycforge/orm-security-providers

Encryption & blind-index providers for [@ycforge/ydb-orm](https://github.com/ycforge/ydb-orm) **v0.2+**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js >=22](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](nodejs.org)
[![npm](https://img.shields.io/npm/v/@ycforge/orm-security-providers.svg)](https://www.npmjs.com/package/@ycforge/orm-security-providers)

## Install

```bash
npm install @ycforge/orm-security-providers @ycforge/ydb-orm
# or
yarn add @ycforge/orm-security-providers @ycforge/ydb-orm
```

> Требует `@ycforge/ydb-orm >= 0.2.0-beta.0 < 0.3.0`: шифротекст хранится в YDB-колонке
> `Bytes` как raw `Uint8Array` (без base64). Base64 используется только
> на границе с KMS REST API.

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

## Quick Start (NestJS)

```ts
import { Module } from '@nestjs/common';
import { YdbCoreModule, YdbModule } from '@ycforge/ydb-orm';
import { YcAuthModule, InjectAuth } from '@ycforge/auth/nestjs';
import { createAuth, authKeyFromFile } from '@ycforge/auth';
import { KmsEncryptionProvider } from '@ycforge/orm-security-providers/yandex-kms';
import { KmsBlindIndexProvider } from '@ycforge/orm-security-providers/hmac-bi';

@Module({
  imports: [
    YcAuthModule.forRoot({
      config: authKeyFromFile(process.env.YDB_AUTHORIZED_KEY_PATH!),
      global: true,
    }),
    YdbCoreModule.forRootAsync({
      useFactory: (auth) => ({
        endpoint: process.env.YDB_ENDPOINT!,
        auth,
        encryptionProvider: new KmsEncryptionProvider({
          keyId: process.env.KMS_KEY_ID!,
          auth,
        }),
        blindIndexProvider: new KmsBlindIndexProvider({
          blindIndexKey: process.env.KMS_BLIND_INDEX_KEY!,
        }),
      }),
      inject: [InjectAuth()],
    }),
    YdbModule.forFeature([UserEntity]),
  ],
})
export class AppModule {}
```

## Quick Start (standalone)

```ts
import { configureEntities, createDriver, createExecutor } from '@ycforge/ydb-orm';
import { createAuth } from '@ycforge/auth';

const auth = createAuth({ type: 'metadata' });
const driver = await createDriver({ endpoint: '...', auth });
const executor = createExecutor(driver, { endpoint: '...', auth });

configureEntities([UserEntity], {
  executor,
  encryptionProvider: new KmsEncryptionProvider({
    keyId: process.env.KMS_KEY_ID!,
    auth,
  }),
  blindIndexProvider: new KmsBlindIndexProvider({ /* ... */ }),
});
```

## Contract (ydb-orm v0.2+)

```ts
interface YdbEncryptionProvider {
  encrypt(plaintext: string, aad: string, context: YdbEncryptionContext): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array, aad: string, context: YdbEncryptionContext): Promise<string>;
}

interface YdbBlindIndexProvider {
  hash(plaintext: string, context: YdbEncryptionContext): Promise<string>;
}
```

`KmsEncryptionProvider` возвращает и принимает **raw ciphertext** (`Uint8Array`) —
ORM кладёт его в колонку `Bytes` без перекодирований. Преобразование base64
выполняется только внутри адаптера при обмене с KMS REST API.

## `@ycforge/orm-security-providers/yandex-kms`

### KmsEncryptionProvider

```ts
new KmsEncryptionProvider(options: KmsEncryptionProviderOptions)
```

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `keyId` | `string` | yes | — | KMS symmetric key ID |
| `auth` | `AuthManager` (`@ycforge/auth`) | yes | — | Ready-made auth manager |
| `apiEndpoint` | `string` | no | `https://kms.yandex` | KMS API base URL |

Methods:

```ts
encrypt(plaintext: string, aad: string, context: YdbEncryptionContext): Promise<Uint8Array>
decrypt(ciphertext: Uint8Array, aad: string, context: YdbEncryptionContext): Promise<string>
```

### Authentication

Authorization is handled entirely by a ready-made `AuthManager` from
[`@ycforge/auth`](https://github.com/ycforge/auth). Create it with
`createAuth(...)` and pass it to `KmsEncryptionProvider`.

The provider requests tokens with usage `'ycloud'`; strategies that don't
support it (`anonymous`, `access_token`, `static`) are rejected by
`@ycforge/auth` with `UnsupportedAuthMethodError`.

```ts
import { createAuth, authKeyFromFile } from '@ycforge/auth';

const auth = createAuth(authKeyFromFile('./authorized_key.json'));

new KmsEncryptionProvider({ keyId: 'aby...', auth });
```

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
import { createAuth, authKeyFromFile } from '@ycforge/auth';

new KmsEncryptionProvider({
  keyId: 'aby...',
  auth: createAuth(authKeyFromFile('./authorized_key.json')),
});
```

#### metadata (production on VM)

```ts
import { createAuth } from '@ycforge/auth';

new KmsEncryptionProvider({
  keyId: 'aby...',
  auth: createAuth({ type: 'metadata' }),
});
```

#### iam_token (quick test)

```bash
yc iam create-token
```

```ts
import { createAuth } from '@ycforge/auth';

new KmsEncryptionProvider({
  keyId: 'aby...',
  auth: createAuth({ type: 'iam_token', token: '<token>' }),
});
```

Static tokens are served as-is; their validity is decided by the server. If
you know the expiry, pass `expiresAt` (`Date`, ISO string or unix ms) — after
that moment `getToken()` throws instead of sending a dead token:

```ts
const auth = createAuth({
  type: 'iam_token',
  token: '<token>',
  expiresAt: '2026-09-01T00:00:00Z',
});
```

### IamTokenManager

```ts
import { createAuth } from '@ycforge/auth';
import { IamTokenManager } from '@ycforge/orm-security-providers/yandex-kms';

const auth = createAuth({ type: 'metadata' });
const manager = new IamTokenManager(auth);
const token = await manager.getToken();
```

## `@ycforge/orm-security-providers/hmac-bi`

### KmsBlindIndexProvider

```ts
new KmsBlindIndexProvider(options: KmsBlindIndexProviderOptions)
```

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `blindIndexKey` | `string` | yes | Canonical padded Base64 key (**≥ 32 bytes decoded**); invalid alphabet, bad padding or non-canonical trailing bits are rejected |

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
import {
  YdbBaseEntity,
  YdbEntity,
  YdbColumn,
  YdbPrimaryColumn,
  YdbEncrypted,
  YdbSecurityAAD,
} from '@ycforge/ydb-orm';

@YdbEntity('users')
class User extends YdbBaseEntity {
  @YdbPrimaryColumn('Uuid')
  uuid!: string;

  // PK участвует в AAD: шифротекст привязан к значению колонки
  @YdbSecurityAAD()
  @YdbPrimaryColumn('Utf8')
  tenant!: string;

  // blind index включён по умолчанию → колонка email_bi (Utf8)
  @YdbEncrypted()
  email!: string;

  // без blind index
  @YdbEncrypted({ blindIndex: false })
  note!: string;

  @YdbColumn('Utf8')
  name!: string;
}
```

Шифротекст хранится в колонке `Bytes`; тип из `@YdbColumn` для
`@YdbEncrypted`-полей указывать не нужно.

CRUD через Active Record:

```ts
// save() шифрует @YdbEncrypted-поля и считает _bi
await User.save(user);

// find() дешифрует обратно
const found = await User.find({ uuid: user.uuid });

// поиск по зашифрованному полю — через blind index
const byEmail = await User.find({ tenant: user.tenant, email: 'alice@example.com' });

// зашифрованный updateBy(): перешифровка + обновление _bi
await User.updateBy(
  { uuid: user.uuid, tenant: user.tenant },
  { email: 'alice+new@example.com' },
);
```

Больше примеров — в [`examples/`](examples):
`nest-module.ts`, `orm-entity.ts`, `basic-encryption.ts`, `blind-index.ts`,
`aad-binding.ts`, `auth-modes.ts`.

## Testing

```bash
yarn test              # unit + ORM-pipeline tests (моки KMS/YDB)
yarn test:integration  # real KMS API (requires .env)
yarn test:cov          # coverage
```

ORM-pipeline тесты (`orm-pipeline.spec.ts`) прогоняют реальный интерфейс
`@ycforge/ydb-orm` (`configureEntities`, декораторы, репозиторий) поверх
in-memory эмуляции YDB и мока KMS API: encrypt/decrypt, blind index поиск,
AAD-привязка, зашифрованный `updateBy()`, хранение `Uint8Array`.

## Project Structure

```
src/
  index.ts                              # root barrel — re-exports all providers
  yandex-kms/
    index.ts                            # barrel for KMS + IAM
    kms-encryption-provider.ts          # encrypt / decrypt via KMS REST API (Uint8Array contract)
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
    e2e.spec.ts                         # mocked KMS roundtrips
    orm-pipeline.spec.ts                # real ydb-orm interface × providers
    integration.spec.ts                 # real KMS API (env-gated)
examples/
  nest-module.ts                        # YdbCoreModule.forRootAsync() + forFeature
  orm-entity.ts                         # standalone pipeline: save/find/updateBy
  basic-encryption.ts
  blind-index.ts
  aad-binding.ts
  auth-modes.ts
```

## License

MIT © [ycforge](https://github.com/ycforge)
