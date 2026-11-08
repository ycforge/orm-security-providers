# AGENTS.md — @ycforge/orm-security-providers

Провайдеры шифрования и blind-index для **@ycforge/ydb-orm**.

## Subpath exports

| Subpath | Что внутри |
|---------|-----------|
| `@ycforge/orm-security-providers/yandex-kms` | `KmsEncryptionProvider` (Yandex Cloud KMS SymmetricCrypto REST API) |
| `@ycforge/orm-security-providers/hmac-bi` | `KmsBlindIndexProvider` (HMAC-SHA256, ключ в памяти) |
| `@ycforge/orm-security-providers` | Ре-экспорт всего (обратная совместимость) |

## Структура

- `src/yandex-kms/kms-encryption-provider.ts` — `KmsEncryptionProvider` (encrypt/decrypt через `https://kms.yandex/kms/v1/keys/{id}:encrypt|decrypt`). Контракт ORM v1+: наружу raw `Uint8Array`, base64 только на границе KMS REST API.
- `src/hmac-bi/hmac-blind-index-provider.ts` — `KmsBlindIndexProvider` (HMAC-SHA256, ключ хранится в памяти).
- `src/__tests__/` — Jest 30, ESM, `--experimental-vm-modules`. `setup.ts` загружает `.env` через `dotenv`. `orm-pipeline.spec.ts` гоняет реальный интерфейс `@ycforge/ydb-orm` (configureEntities + декораторы) поверх in-memory YDB-эмуляции и мока KMS.

## Команды

| Команда | Описание |
|---------|----------|
| `yarn build` | `tsc -p tsconfig.build.json` → `dist/` |
| `yarn test` | Unit + e2e тесты (моки) |
| `yarn test:integration` | Реальный KMS API (требует `.env`) |
| `yarn test:cov` | Покрытие |
| `yarn lint` | ESLint + autofix |
| `yarn format` | Prettier |

## Ключевые правила

- **Пакетный менеджер** — yarn v1.
- **Node >= 22** (ESM, `node:crypto`, `node:fetch`).
- **Endpoint KMS API** — `https://kms.yandex` (НЕ `kms.api.cloud.yandex.net` —后者 возвращает 404 на криптооперациях).
- **AAD** — передаётся как `aadContext` (base64): purpose/version, domain, таблица, поле, полный PK и дополнительный AAD.
- **Blind index** — HMAC-SHA256 с ключом из `KMS_BLIND_INDEX_KEY`. HMAC включает domain/tableName/fieldName, но не PK.
- **Секреты** (`authorized_key.json`, `.env`, `KMS_BLIND_INDEX_KEY`) не коммитить и не выводить.
- **Peer dependency** — `@ycforge/ydb-orm >=1.0.0 <2.0.0` (контракт `Uint8Array`). Для локальной разработки devDependency — опубликованная `1.0.0`.
- **Контракт шифрования** — `encrypt(): Promise<Uint8Array>`, `decrypt(ciphertext: Uint8Array): Promise<string>`; шифротекст хранится в YDB-колонке `Bytes`. Не возвращать base64/string наружу и не добавлять legacy-совместимость со старым string API.

## Авторизация

Провайдер больше не знает о способах авторизации. В `KmsEncryptionProvider`
передаётся готовый `AuthManager` из **@ycforge/auth**
(`file:../ycforge-auth` при локальной разработке, `^0.1.0` в публикации).
Токен запрашивается с usage `'ycloud'` — стратегии `anonymous`/`access_token`/`static`
отклоняются с `UnsupportedAuthMethodError`.

```ts
import { createAuth, authKeyFromFile } from '@ycforge/auth';

const auth = createAuth(authKeyFromFile('./authorized_key.json'));
new KmsEncryptionProvider({ keyId: 'aby...', auth });
```

Поддерживаемые стратегии `createAuth` для KMS:
- `{ type: 'metadata' }` — метаданные VM (только внутри Yandex Cloud);
- `authKeyFromFile(path)` — JWT сервисного аккаунта → IAM-токен;
- `{ type: 'iam_token', token, expiresAt? }` — готовый IAM-токен.

Для `auth_key` нужны права `kms.keys.encrypterDecrypter` на ключ.

## Добавление нового провайдера

1. Создать поддиректорию в `src/` (например, `src/new-provider/`).
2. Добавить `index.ts` barrel с экспортом.
3. Добавить subpath в `package.json` → `exports`.
4. Ре-экспортировать из корневого `src/index.ts`.
5. Обновить `README.md`.

## Добавление нового теста

1. Unit-тесты мокают `global.fetch` — см. `kms-encryption-provider.spec.ts`.
2. Integration-тесты реальны — пропускаются если `.env` не задан (`loadKmsTestConfigFromEnv()` возвращает `null`).
3. После изменений в API — обновить `README.md` и `examples/`.

## Authenticated context

KMS AAD всегда включает purpose/version, domain, таблицу, поле, полный PK и aad.
Недостающий контекст — ошибка до сети. HMAC имеет отдельный purpose и включает
таблицу/поле/domain/plaintext, без PK. Domain по умолчанию default; при общем
ключе между БД нужен явный уникальный domain. Формат beta изменён намеренно,
без legacy fallback/миграций. Перед релизом провайдеров требуется согласованное
обновление ORM (canonical PK, projection retention, lazy binding guard).
