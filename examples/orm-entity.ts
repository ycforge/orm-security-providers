/**
 * Полный конвейер @ycforge/ydb-orm (standalone) с KMS-провайдерами:
 * шифрование на save(), дешифровка на find(), поиск через blind index,
 * зашифрованный updateBy() и AAD-привязка через @YdbSecurityAAD.
 *
 * Шифротекст хранится в YDB-колонке `Bytes` как raw Uint8Array
 * (контракт ydb-orm v0.2+); base64 остаётся внутри KMS REST API.
 *
 * Run (нужны YDB_ENDPOINT и KMS-доступ):
 *   npx tsx examples/orm-entity.ts
 */
import {
  configureEntities,
  createDriver,
  createExecutor,
  YdbBaseEntity,
  YdbColumn,
  YdbEncrypted,
  YdbEntity,
  YdbPrimaryColumn,
  YdbSecurityAAD,
} from '@ycforge/ydb-orm';
import { createAuth, authKeyFromFile } from '@ycforge/auth';
import { KmsEncryptionProvider } from '../src/yandex-kms/kms-encryption-provider.js';
import { KmsBlindIndexProvider } from '../src/hmac-bi/hmac-blind-index-provider.js';

@YdbEntity('example_users')
class UserEntity extends YdbBaseEntity {
  @YdbPrimaryColumn('Uuid')
  uuid!: string;

  // PK участвует в AAD: шифротекст привязан к строке
  @YdbSecurityAAD()
  @YdbPrimaryColumn('Utf8')
  tenant!: string;

  @YdbEncrypted({ blindIndex: true })
  email!: string;

  @YdbEncrypted({ blindIndex: false })
  note!: string;

  @YdbColumn('Utf8')
  name!: string;
}

const auth = createAuth(
  authKeyFromFile(process.env.YDB_AUTHORIZED_KEY_PATH!),
);

const driver = await createDriver({ endpoint: process.env.YDB_ENDPOINT!, auth });
const executor = createExecutor(driver, { endpoint: process.env.YDB_ENDPOINT!, auth });

configureEntities([UserEntity], {
  executor,
  encryptionProvider: new KmsEncryptionProvider({
    keyId: process.env.KMS_KEY_ID!,
    auth,
  }),
  blindIndexProvider: new KmsBlindIndexProvider({
    blindIndexKey: process.env.KMS_BLIND_INDEX_KEY!,
  }),
});

// ── Создание: email/note шифруются на save() ──────────────────────
const user = new UserEntity();
user.tenant = 'tenant-1';
user.email = 'alice@example.com';
user.note = 'закрытая заметка';
user.name = 'Alice';
await UserEntity.save(user);
console.log('saved:', user.uuid);

// ── Чтение: поля дешифруются автоматически ────────────────────────
const found = await UserEntity.find({ uuid: user.uuid, tenant: user.tenant });
console.log('decrypted email:', found?.email);

// ── Поиск по зашифрованному полю через blind index ────────────────
const byEmail = await UserEntity.find({
  tenant: user.tenant,
  email: 'alice@example.com',
});
console.log('found by blind index:', byEmail?.uuid === user.uuid);

// ── Зашифрованный updateBy(): перешифрование + обновление индекса ─
const updated = await UserEntity.updateBy(
  { uuid: user.uuid, tenant: user.tenant },
  { email: 'alice+new@example.com' },
);
console.log('updated rows:', updated);

const oldEmail = await UserEntity.find({
  tenant: user.tenant,
  email: 'alice@example.com',
});
console.log('old email searchable:', oldEmail !== null);

await driver.close();
