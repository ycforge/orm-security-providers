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

afterEach(() => {
  globalThis.fetch = originalFetch;
  jest.clearAllMocks();
});

describe("IamTokenManager", () => {
  describe("iam_token auth", () => {
    it("returns the provided token directly", async () => {
      const manager = new IamTokenManager("iam_token", {
        iam_token: "test-iam-token",
      });

      const token = await manager.getToken();

      expect(token).toBe("test-iam-token");
    });

    it("does not call fetch", async () => {
      globalThis.fetch = jest.fn() as any;

      const manager = new IamTokenManager("iam_token", {
        iam_token: "test-iam-token",
      });

      await manager.getToken();

      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    it("caches the token and returns it on subsequent calls", async () => {
      globalThis.fetch = jest.fn() as any;

      const manager = new IamTokenManager("iam_token", {
        iam_token: "cached-token",
      });

      const t1 = await manager.getToken();
      const t2 = await manager.getToken();

      expect(t1).toBe("cached-token");
      expect(t2).toBe("cached-token");
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    it("throws when iam_token is not provided", () => {
      expect(() => new IamTokenManager("iam_token", {})).toThrow(
        "iam_token is required for iam_token authentication",
      );
    });
  });

  describe("meta auth", () => {
    it("fetches token from metadata service", async () => {
      mockFetch(
        jsonResponse({
          access_token: "meta-token-abc",
          expires_in: 3600,
        }),
      );

      const manager = new IamTokenManager("meta", {});
      const token = await manager.getToken();

      expect(token).toBe("meta-token-abc");
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        { headers: { "Metadata-Flavor": "Google" } },
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

      const manager = new IamTokenManager("meta", {});

      const t1 = await manager.getToken();
      const t2 = await manager.getToken();

      expect(t1).toBe("token-1");
      expect(t2).toBe("token-1");
      expect(callCount).toBe(1);
    });

    it("refreshes token when expired", async () => {
      let callCount = 0;
      globalThis.fetch = jest.fn(() => {
        callCount++;
        return Promise.resolve(
          jsonResponse({
            access_token: `token-${callCount}`,
            expires_in: 0,
          }),
        );
      });

      const manager = new IamTokenManager("meta", {});

      const t1 = await manager.getToken();
      const t2 = await manager.getToken();

      expect(t1).toBe("token-1");
      expect(t2).toBe("token-2");
      expect(callCount).toBe(2);
    });

    it("throws on metadata service failure", async () => {
      mockFetch(errorResponse(500, "Internal Server Error"));

      const manager = new IamTokenManager("meta", {});

      await expect(manager.getToken()).rejects.toThrow(
        "Metadata token request failed: 500",
      );
    });

    it("throws when access_token is missing in response", async () => {
      mockFetch(jsonResponse({ expires_in: 3600 }));

      const manager = new IamTokenManager("meta", {});

      await expect(manager.getToken()).rejects.toThrow(
        "No access_token in metadata response",
      );
    });

    it("handles missing expires_in with default 3600s", async () => {
      mockFetch(jsonResponse({ access_token: "token-no-exp" }));

      const manager = new IamTokenManager("meta", {});

      const token = await manager.getToken();
      expect(token).toBe("token-no-exp");
    });
  });

  describe("auth_key auth", () => {
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

      const manager = new IamTokenManager("auth_key", {
        authorized_key_path: "/path/to/key.json",
      });

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

    it("throws when authorized_key_path is not provided", () => {
      expect(() => new IamTokenManager("auth_key", {})).toThrow(
        "authorized_key_path is required for auth_key authentication",
      );
    });

    it("throws on invalid key file", () => {
      mockReadFileSync.mockReturnValue(JSON.stringify({ id: "key-id" }));

      expect(
        () =>
          new IamTokenManager("auth_key", {
            authorized_key_path: "/path/to/bad.json",
          }),
      ).toThrow("Invalid authorized_key.json");
    });

    it("throws on IAM token exchange failure", async () => {
      mockFetch(errorResponse(401, "Unauthorized"));

      const manager = new IamTokenManager("auth_key", {
        authorized_key_path: "/path/to/key.json",
      });

      await expect(manager.getToken()).rejects.toThrow(
        "IAM token exchange failed: 401",
      );
    });

    it("throws when iamToken is missing in response", async () => {
      mockFetch(jsonResponse({}));

      const manager = new IamTokenManager("auth_key", {
        authorized_key_path: "/path/to/key.json",
      });

      await expect(manager.getToken()).rejects.toThrow(
        "No iamToken in response",
      );
    });

    it("caches exchanged token", async () => {
      mockFetch(
        jsonResponse({
          iamToken: "cached-iam-token",
          expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        }),
      );

      const manager = new IamTokenManager("auth_key", {
        authorized_key_path: "/path/to/key.json",
      });

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

      const manager = new IamTokenManager("auth_key", {
        authorized_key_path: "/path/to/key.json",
      });

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
});
