import { YCLOUD_AUTH_USAGE, type AuthManager } from "@ycforge/auth";

/**
 * Управление IAM-токеном для доступа к Yandex Cloud KMS API.
 *
 * Полностью делегирует авторизацию переданному {@link AuthManager} из
 * `@ycforge/auth`. Токен запрашивается с usage {@link YCLOUD_AUTH_USAGE} —
 * стратегии, не поддерживающие этот usage (например, `anonymous`), отклоняются
 * самим `@ycforge/auth` через {@link UnsupportedAuthMethodError}.
 */
export class IamTokenManager {
  readonly #manager: AuthManager;

  constructor(auth: AuthManager) {
    if (!auth) {
      throw new Error("auth (AuthManager) is required");
    }
    this.#manager = auth;
  }

  async getToken(): Promise<string> {
    return this.#manager.getToken(YCLOUD_AUTH_USAGE);
  }
}
