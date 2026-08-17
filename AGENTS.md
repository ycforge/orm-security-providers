# AGENTS.md — @ycforge/orm-security-providers

Провайдеры шифрования и blind-index для **@ycforge/ydb-orm**.

## Subpath exports

| Subpath | Что внутри |
|---------|-----------|
| `@ycforge/orm-security-providers/yandex-kms` | `KmsEncryptionProvider`, `IamTokenManager` (Yandex Cloud KMS SymmetricCrypto REST API) |
| `@ycforge/orm-security-providers/hmac-bi` | `KmsBlindIndexProvider` (HMAC-SHA256, ключ в памяти) |
| `@ycforge/orm-security-providers` | Ре-экспорт всего (обратная совместимость) |

## Структура

- `src/yandex-kms/kms-encryption-provider.ts` — `KmsEncryptionProvider` (encrypt/decrypt через `https://kms.yandex/kms/v1/keys/{id}:encrypt|decrypt`).
- `src/yandex-kms/iam-token-manager.ts` — `IamTokenManager` (3 режима: `meta`, `auth_key`, `iam_token`).
- `src/hmac-bi/hmac-blind-index-provider.ts` — `KmsBlindIndexProvider` (HMAC-SHA256, ключ хранится в памяти).
- `src/__tests__/` — Jest 30, ESM, `--experimental-vm-modules`. `setup.ts` загружает `.env` через `dotenv`.

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
- **AAD** — передаётся как `aadContext` (base64). Привязывает ciphertext к значениям `@YdbSecurityAAD`-полей.
- **Blind index** — HMAC-SHA256 с ключом из `KMS_BLIND_INDEX_KEY`. `context` в `hash()` игнорируется.
- **Секреты** (`authorized_key.json`, `.env`, `KMS_BLIND_INDEX_KEY`) не коммитить и не выводить.
- **Peer dependency** — `@ycforge/ydb-orm >=0.1.0`. Для локальной разработки `devDependencies` ссылаются на `file:../ydb-orm`.

## Авторизация

| Режим | Описание | Опции |
|-------|----------|-------|
| `meta` | Метаданные VM (только внутри Yandex Cloud) | — |
| `auth_key` | JWT сервисного аккаунта → IAM-токен | `authorized_key_path` |
| `iam_token` | Готовый IAM-токен (без обновления) | `iam_token` |

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
