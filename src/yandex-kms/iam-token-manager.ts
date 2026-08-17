import crypto from 'node:crypto';
import fs from 'node:fs';

const IAM_TOKEN_URL = 'https://iam.api.cloud.yandex.net/iam/v1/tokens';
const METADATA_TOKEN_URL =
  'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token';
const TOKEN_EXPIRY_LEEWAY_MS = 60_000;

export type KmsAuthMethod = 'meta' | 'auth_key' | 'iam_token';

export interface KmsAuthOptions {
  /** Путь к authorized_key.json (service account key). */
  authorized_key_path?: string;
  /** IAM-токен напрямую (без автоматического обновления). */
  iam_token?: string;
}

interface IamTokenResponse {
  iamToken?: string;
  expiresAt?: string;
}

interface MetadataTokenResponse {
  access_token?: string;
  expires_in?: number;
}

interface IamJWTKeyCredentials {
  keyId: string;
  serviceAccountId: string;
  privateKey: string;
}

function parseTimestamp(ts: unknown): Date {
  if (!ts) return new Date(Date.now() + 3600_000);
  if (ts instanceof Date) return ts;
  if (typeof ts === 'string') return new Date(ts);
  if (typeof ts === 'number') return new Date(ts);
  return new Date(Date.now() + 3600_000);
}

/**
 * Управление IAM-токеном для доступа к Yandex Cloud KMS API.
 *
 * Поддерживает три способа авторизации:
 * - `meta` — metadata-сервис виртуальной машины Yandex Cloud
 * - `auth_key` — обмен JWT сервисного аккаунта на IAM-токен
 * - `iam_token` — готовый IAM-токен (без автоматического обновления)
 */
export class IamTokenManager {
  #promise: Promise<string> | null = null;
  #token: { value: string; expired_at: Date } | null = null;
  #authMethod: KmsAuthMethod;
  #authOptions: KmsAuthOptions;
  #credentials?: IamJWTKeyCredentials;

  constructor(authMethod: KmsAuthMethod, authOptions: KmsAuthOptions) {
    this.#authMethod = authMethod;
    this.#authOptions = authOptions;

    if (authMethod === 'auth_key') {
      if (!authOptions.authorized_key_path) {
        throw new Error(
          'authorized_key_path is required for auth_key authentication',
        );
      }
      this.#credentials = this.#loadAuthorizedKey(
        authOptions.authorized_key_path,
      );
    }

    if (authMethod === 'iam_token') {
      if (!authOptions.iam_token) {
        throw new Error('iam_token is required for iam_token authentication');
      }
      this.#token = {
        value: authOptions.iam_token,
        expired_at: new Date(Date.now() + 365 * 24 * 3600_000),
      };
    }
  }

  async getToken(): Promise<string> {
    if (
      this.#token &&
      this.#token.expired_at.getTime() - TOKEN_EXPIRY_LEEWAY_MS > Date.now()
    ) {
      return this.#token.value;
    }

    if (this.#promise) {
      return this.#promise;
    }

    this.#promise = this.#fetchToken().finally(() => {
      this.#promise = null;
    });

    return this.#promise;
  }

  async #fetchToken(): Promise<string> {
    switch (this.#authMethod) {
      case 'meta':
        return this.#fetchMetadataToken();
      case 'auth_key':
        return this.#exchangeJwtForIamToken();
      case 'iam_token':
        return this.#token!.value;
    }
  }

  async #fetchMetadataToken(): Promise<string> {
    const response = await fetch(METADATA_TOKEN_URL, {
      headers: { 'Metadata-Flavor': 'Google' },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(
        `Metadata token request failed: ${response.status} ${body}`,
      );
    }

    const data = (await response.json()) as MetadataTokenResponse;
    if (!data.access_token) {
      throw new Error('No access_token in metadata response');
    }

    const expiresIn = data.expires_in ?? 3600;
    this.#token = {
      value: data.access_token,
      expired_at: new Date(Date.now() + expiresIn * 1000),
    };

    return this.#token.value;
  }

  async #exchangeJwtForIamToken(): Promise<string> {
    const jwt = this.#generateJWT();

    const response = await fetch(IAM_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(
        `IAM token exchange failed: ${response.status} ${body}`,
      );
    }

    const data = (await response.json()) as IamTokenResponse;
    if (!data.iamToken) {
      throw new Error('No iamToken in response');
    }

    const expiresAt = parseTimestamp(data.expiresAt);
    this.#token = {
      value: data.iamToken,
      expired_at: expiresAt,
    };

    return this.#token.value;
  }

  #generateJWT(): string {
    const creds = this.#credentials!;
    const now = Math.floor(Date.now() / 1000);

    const header = {
      alg: 'PS256',
      typ: 'JWT',
      kid: creds.keyId,
    };

    const payload = {
      iss: creds.serviceAccountId,
      sub: creds.serviceAccountId,
      aud: IAM_TOKEN_URL,
      iat: now,
      exp: now + 3600,
    };

    const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
      'base64url',
    );
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
      'base64url',
    );
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const privateKey = crypto.createPrivateKey(creds.privateKey);
    const signature = crypto.sign('sha256', Buffer.from(signingInput), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    });

    return `${signingInput}.${signature.toString('base64url')}`;
  }

  #loadAuthorizedKey(path: string): IamJWTKeyCredentials {
    const raw = fs.readFileSync(path, 'utf-8');
    const json = JSON.parse(raw);

    if (!json.id || !json.service_account_id || !json.private_key) {
      throw new Error(
        `Invalid authorized_key.json at ${path}. Expected fields: id, service_account_id, private_key`,
      );
    }

    return {
      keyId: json.id,
      serviceAccountId: json.service_account_id,
      privateKey: json.private_key,
    };
  }
}
