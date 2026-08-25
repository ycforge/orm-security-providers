/**
 * NestJS: YdbCoreModule.forRootAsync() + провайдеры безопасности.
 *
 * Аутентификация централизована через @ycforge/auth/nestjs:
 * YcAuthModule.forRoot() регистрирует AuthManager, который затем
 * инжектируется в useFactory и используется и драйвером YDB, и
 * KMS-провайдером шифрования.
 */
import { Module } from '@nestjs/common';
import {
  YdbCoreModule,
  YdbModule,
  YdbBaseEntity,
  YdbEntity,
  YdbPrimaryColumn,
  YdbColumn,
  YdbEncrypted,
} from '@ycforge/ydb-orm';
import { YcAuthModule, InjectAuth } from '@ycforge/auth/nestjs';
import { authKeyFromFile } from '@ycforge/auth';
import { KmsEncryptionProvider } from '@ycforge/orm-security-providers/yandex-kms';
import { KmsBlindIndexProvider } from '@ycforge/orm-security-providers/hmac-bi';

@YdbEntity('users')
export class UserEntity extends YdbBaseEntity {
  @YdbPrimaryColumn('Uuid')
  uuid!: string;

  @YdbEncrypted({ blindIndex: true })
  email!: string;

  @YdbColumn('Utf8')
  name!: string;
}

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
