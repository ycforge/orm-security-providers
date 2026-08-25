import { jest } from "@jest/globals";
import crypto from "node:crypto";

const mockReadFileSync = jest.fn() as jest.MockedFunction<
  (path: string, encoding: BufferEncoding) => string
>;

jest.unstable_mockModule("node:fs", () => ({
  default: { readFileSync: mockReadFileSync },
}));

await import("node:fs");
const { IamTokenManager } = await import("../yandex-kms/iam-token-manager.js");
const {
  createAuth,
  authKeyFromFile,
  UnsupportedAuthMethodError,
} = await import("@ycforge/auth");

const originalFetch = globalThis.fetch;

function mockFetch(response: Response) {
  globalThis.fetch = jest.fn(() => Promise.resolve(response));
}

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

function errorResponse(status: number, body: string): Response {
  return {
    ok: false,
    status,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(body),
  } as Response;
}

/**
 * @ycforge/auth ретраит сетевые/HTTP ошибки с backoff (5 попыток).
 * Чтобы не ждать реальные ~111 c backoff'а, прокручиваем fake timers.
 */
async function expectRejectsWithRetry(
  promise: Promise<unknown>,
  matcher: string | RegExp,
) {
  const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
  jest.useFakeTimers();
  try {
    const assertion = expect(promise).rejects.toThrow(matcher);
    await jest.advanceTimersByTimeAsync(200_000);
    await assertion;
  } finally {
    jest.useRealTimers();
    warnSpy.mockRestore();
  }
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.clearAllMocks();
});

describe("IamTokenManager", () => {
  it("throws when auth is not provided", () => {
    expect(() => new IamTokenManager(undefined as any)).toThrow(
      /auth \(AuthManager\) is required/,
    );
  });

  it("delegates getToken() to AuthManager with usage 'ycloud'", async () => {
    globalThis.fetch = jest.fn() as any;

    const auth = createAuth({ type: "iam_token", token: "auth-token" });
    const manager = new IamTokenManager(auth);

    await expect(manager.getToken()).resolves.toBe("auth-token");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  describe("createAuth({ type: 'iam_token' })", () => {
    it("returns the provided token directly", async () => {
      const auth = createAuth({ type: "iam_token", token: "test-iam-token" });
      const manager = new IamTokenManager(auth);

      const token = await manager.getToken();

      expect(token).toBe("test-iam-token");
    });

    it("does not call fetch", async () => {
      globalThis.fetch = jest.fn() as any;

      const auth = createAuth({ type: "iam_token", token: "test-iam-token" });
      const manager = new IamTokenManager(auth);

      await manager.getToken();

      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    it("caches the token and returns it on subsequent calls", async () => {
      globalThis.fetch = jest.fn() as any;

      const auth = createAuth({ type: "iam_token", token: "cached-token" });
      const manager = new IamTokenManager(auth);

      const t1 = await manager.getToken();
      const t2 = await manager.getToken();

      expect(t1).toBe("cached-token");
      expect(t2).toBe("cached-token");
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });
  });

  describe("createAuth({ type: 'metadata' })", () => {
    it("fetches token from metadata service", async () => {
      mockFetch(
        jsonResponse({
          access_token: "meta-token-abc",
          expires_in: 3600,
        }),
      );

      const auth = createAuth({ type: "metadata" });
      const manager = new IamTokenManager(auth);
      const token = await manager.getToken();

      expect(token).toBe("meta-token-abc");
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        expect.objectContaining({
          headers: { "Metadata-Flavor": "Google" },
        }),
      );
    });

    it("caches token until near expiry", async () => {
      let callCount = 0;
      globalThis.fetch = jest.fn(() => {
        callCount++;
        return Promise.resolve(
          jsonResponse({
            access_token: `token-${callCount}`,
            expires_in: 3600,
          }),
        );
      });

      const auth = createAuth({ type: "metadata" });
      const manager = new IamTokenManager(auth);

      const t1 = await manager.getToken();
      const t2 = await manager.getToken();

      expect(t1).toBe("token-1");
      expect(t2).toBe("token-1");
      expect(callCount).toBe(1);
    });

    it("throws on metadata service failure (after retries)", async () => {
      mockFetch(errorResponse(500, "Internal Server Error"));

      const auth = createAuth({ type: "metadata" });
      const manager = new IamTokenManager(auth);

      await expectRejectsWithRetry(
        manager.getToken(),
        "Metadata token request failed with status 500",
      );
    });
  });

  describe("createAuth(authKeyFromFile(...))", () => {
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    const authorizedKey = {
      id: "key-id-123",
      service_account_id: "sa-id-456",
      private_key: privateKey,
    };

    beforeEach(() => {
      mockReadFileSync.mockReturnValue(JSON.stringify(authorizedKey));
    });

    it("loads key from file and exchanges JWT for IAM token", async () => {
      mockFetch(
        jsonResponse({
          iamToken: "exchanged-iam-token",
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        }),
      );

      const auth = createAuth(authKeyFromFile("/path/to/key.json"));
      const manager = new IamTokenManager(auth);
      const token = await manager.getToken();

      expect(token).toBe("exchanged-iam-token");
      expect(mockReadFileSync).toHaveBeenCalledWith(
        "/path/to/key.json",
        "utf-8",
      );
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "https://iam.api.cloud.yandex.net/iam/v1/tokens",
        expect.objectContaining({
          method: "POST",
          headers: { "Content-Type": "application/json" },
        }),
      );
    });

    it("throws on IAM token exchange failure (after retries)", async () => {
      mockFetch(errorResponse(401, "Unauthorized"));

      const auth = createAuth(authKeyFromFile("/path/to/key.json"));
      const manager = new IamTokenManager(auth);

      await expectRejectsWithRetry(
        manager.getToken(),
        "IAM token exchange failed with status 401",
      );
    });

    it("caches exchanged token", async () => {
      mockFetch(
        jsonResponse({
          iamToken: "cached-iam-token",
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        }),
      );

      const auth = createAuth(authKeyFromFile("/path/to/key.json"));
      const manager = new IamTokenManager(auth);

      const t1 = await manager.getToken();
      const t2 = await manager.getToken();

      expect(t1).toBe("cached-iam-token");
      expect(t2).toBe("cached-iam-token");
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });

    it("deduplicates concurrent token requests", async () => {
      mockFetch(
        jsonResponse({
          iamToken: "concurrent-token",
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        }),
      );

      const auth = createAuth(authKeyFromFile("/path/to/key.json"));
      const manager = new IamTokenManager(auth);

      const [t1, t2, t3] = await Promise.all([
        manager.getToken(),
        manager.getToken(),
        manager.getToken(),
      ]);

      expect(t1).toBe("concurrent-token");
      expect(t2).toBe("concurrent-token");
      expect(t3).toBe("concurrent-token");
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });
  });

  describe("unsupported strategy for 'ycloud' usage", () => {
    it("throws UnsupportedAuthMethodError for anonymous auth", async () => {
      const auth = createAuth({ type: "anonymous" });
      const manager = new IamTokenManager(auth);

      await expect(manager.getToken()).rejects.toThrow(
        UnsupportedAuthMethodError,
      );
      await expect(manager.getToken()).rejects.toThrow(
        'not supported for usage "ycloud"',
      );
    });
  });
});
