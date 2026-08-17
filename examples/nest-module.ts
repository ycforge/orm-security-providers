/**
 * NestJS module integration with @ycforge/ydb-orm + security providers.
 */
import { Module } from '@nestjs/common';
import { YdbOrmModule } from '@ycforge/ydb-orm';
import { KmsEncryptionProvider } from '@ycforge/orm-security-providers/yandex-kms';
import { KmsBlindIndexProvider } from '@ycforge/orm-security-providers/hmac-bi';

@Module({
  imports: [
    YdbOrmModule.forRoot({
      connection: {
        endpoint: process.env.YDB_ENDPOINT!,
        database: process.env.YDB_DATABASE!,
      },
      encryption: new KmsEncryptionProvider({
        keyId: process.env.KMS_KEY_ID!,
        auth_type: 'auth_key',
        authOptions: {
          authorized_key_path: process.env.KMS_AUTHORIZED_KEY_PATH!,
        },
      }),
      blindIndex: new KmsBlindIndexProvider({
        blindIndexKey: process.env.KMS_BLIND_INDEX_KEY!,
      }),
    }),
  ],
})
export class AppModule {}
