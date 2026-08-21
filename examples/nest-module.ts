/**
 * NestJS: YdbCoreModule.forRootAsync() + провайдеры безопасности.
 *
 * encryptionProvider / blindIndexProvider передаются в опциях модуля
 * и попадают во все сущности, зарегистрированные через forFeature().
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
  YdbSecurityAAD,
} from '@ycforge/ydb-orm';
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
    YdbCoreModule.forRootAsync({
      useFactory: () => ({
        endpoint: process.env.YDB_ENDPOINT!,
        auth_type: 'auth_key' as const,
        authOptions: {
          authorized_key_path: process.env.YDB_AUTHORIZED_KEY_PATH!,
        },
        encryptionProvider: new KmsEncryptionProvider({
          keyId: process.env.KMS_KEY_ID!,
          auth_type: 'auth_key',
          authOptions: {
            authorized_key_path: process.env.KMS_AUTHORIZED_KEY_PATH!,
          },
        }),
        blindIndexProvider: new KmsBlindIndexProvider({
          blindIndexKey: process.env.KMS_BLIND_INDEX_KEY!,
        }),
      }),
    }),
    YdbModule.forFeature([UserEntity]),
  ],
})
export class AppModule {}
