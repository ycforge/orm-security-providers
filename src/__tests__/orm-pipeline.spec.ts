/**
 * Интеграционные тесты с реальным интерфейсом @ycforge/ydb-orm.
 *
 * Полный конвейер ORM (save → шифрование → INSERT → SELECT → дешифровка,
 * blind index поиск, AAD, зашифрованный updateBy()) поверх провайдеров
 * из этого пакета:
 * - KMS REST API эмулируется подменой global.fetch;
 * - YDB эмулируется in-memory executor'ом с поддержкой UPSERT/SELECT/UPDATE,
 *   которую использует configureEntities().
 *
 * Base64 появляется только внутри KMS-адаптера: в БД лежат raw Uint8Array
 * (колонка Bytes), как и требует контракт ydb-orm v0.2+.
 */
import "reflect-metadata";
import { randomBytes } from "node:crypto";
import { jest } from "@jest/globals";
import {
  configureEntities,
  YdbBaseEntity,
  YdbColumn,
  YdbEncrypted,
  YdbEntity,
  YdbPrimaryColumn,
  YdbSecurityAAD,
} from "@ycforge/ydb-orm";
import type { YdbExecutor } from "@ycforge/ydb-orm";
import { KmsEncryptionProvider } from "../yandex-kms/kms-encryption-provider.js";
import { KmsBlindIndexProvider } from "../hmac-bi/hmac-blind-index-provider.js";

// ─────────────────────────────────────────────────────────────
// In-memory YDB emulator
// ─────────────────────────────────────────────────────────────

interface CapturedQuery {
  sql: string;
  params: Record<string, unknown>;
}

/** Разворачивает обёртки значений @ydbjs/value (Uuid/Utf8/Bytes/Optional…). */
function unwrapValue(v: unknown): unknown {
  if (v === null || v === undefined) return null;
  if (typeof v === "object" && "item" in (v as any)) {
    const item = (v as any).item;
    return item === null || item === undefined ? null : unwrapValue(item);
  }
  if (ArrayBuffer.isView(v)) return v;
  if (v instanceof Date) return v;
  if (typeof v === "object" && "value" in (v as any)) {
    const inner = (v as any).value;
    // Uuid: .value нормализуется в bigint, строка восстанавливается через toString()
    if (
      typeof inner === "bigint" &&
      "low128" in (v as any) &&
      "high128" in (v as any)
    ) {
      return (v as { toString(): string }).toString();
    }
    if (ArrayBuffer.isView(inner))
      return new Uint8Array(
        inner.buffer.slice(
          inner.byteOffset,
          inner.byteOffset + inner.byteLength,
        ),
      );
    if (
      inner === null ||
      ["string", "number", "bigint", "boolean"].includes(typeof inner)
    ) {
      return inner;
    }
    return (v as { toString(): string }).toString();
  }
  return v;
}

class FakeYdb {
  readonly executed: CapturedQuery[] = [];
  readonly #tables = new Map<
    string,
    { pk: string[]; rows: Record<string, any>[] }
  >();

  registerTable(name: string, pk: string[]): void {
    this.#tables.set(name, { pk, rows: [] });
  }

  rows(name: string): Record<string, any>[] {
    return this.#tables.get(name)?.rows ?? [];
  }

  /** Создаёт YdbExecutor-совместимую функцию (tagged template). */
  executor(): YdbExecutor {
    const exec = ((strings: TemplateStringsArray) => {
      const sqlTemplate = strings[0];
      const params: Record<string, unknown> = {};

      const query = {
        parameter(name: string, value: unknown) {
          params[name] = unwrapValue(value);
          return query;
        },
        timeout() {
          return query;
        },
        signal() {
          return query;
        },
        cancel() {},
        then: (
          resolve: (value: any) => unknown,
          reject: (reason?: unknown) => unknown,
        ) => this.#run(sqlTemplate, params).then(resolve, reject),
        [Symbol.toStringTag]: "Promise",
      } as any;

      return query as unknown as YdbExecutor extends infer T
        ? T extends (...args: any[]) => infer R
          ? ReturnType<() => R>
          : never
        : never;
    }) as unknown as YdbExecutor;

    return exec;
  }

  #run(
    sqlRaw: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, any>[][]> {
    return Promise.resolve(this.#exec(sqlRaw, params));
  }

  #exec(
    sqlRaw: string,
    params: Record<string, unknown>,
  ): Record<string, any>[][] {
    const sql = sqlRaw.replace(/\s+/g, " ").trim();
    this.executed.push({ sql, params });

    const upsert = sql.match(
      /^UPSERT INTO `(\w+)` \(([^)]*)\) VALUES \(([^)]*)\)$/,
    );
    if (upsert) {
      const [, table, colsRaw, valsRaw] = upsert;
      const cols = colsRaw.split(",").map((c) => c.trim().replace(/`/g, ""));
      const names = valsRaw.split(",").map((v) => v.trim().replace(/^\$/, ""));
      const row: Record<string, any> = {};
      cols.forEach((c, i) => {
        row[c] = params[names[i]];
      });

      const store = this.#tables.get(table);
      if (!store) throw new Error(`FakeYdb: unknown table "${table}"`);
      const keyOf = (r: Record<string, any>) =>
        JSON.stringify(store.pk.map((f) => r[f]));
      const key = keyOf(row);
      const idx = store.rows.findIndex((r) => keyOf(r) === key);
      if (idx >= 0) store.rows[idx] = row;
      else store.rows.push(row);
      return [];
    }

    const update = sql.match(
      /^UPDATE `(\w+)` SET (.+?)( WHERE .+?)? RETURNING (.+)$/,
    );
    if (update) {
      const [, table, setRaw, whereRaw] = update;
      const store = this.#tables.get(table);
      if (!store) throw new Error(`FakeYdb: unknown table "${table}"`);

      const sets: Record<string, unknown> = {};
      for (const [, col, name] of setRaw.matchAll(/`(\w+)` = \$(\w+)/g)) {
        sets[col] = params[name];
      }
      const conditions = this.#parseConditions(whereRaw ?? "", params);

      for (const row of store.rows) {
        if (!this.#matches(row, conditions)) continue;
        Object.assign(row, sets);
      }
      // RETURNING * / RETURNING `pk` — возвращаем полные строки-клоны
      // (ORM мутирует результат дешифровкой), count считает length.
      return [
        store.rows
          .filter((r) => this.#matches(r, conditions))
          .map((r) => ({ ...r })),
      ];
    }

    const select = sql.match(
      /^SELECT .+? FROM `(\w+)`( WHERE .+?)?( LIMIT (\d+))?( OFFSET (\d+))?$/,
    );
    if (select) {
      const [, table, whereRaw, , limitRaw, , offsetRaw] = select;
      const store = this.#tables.get(table);
      if (!store) throw new Error(`FakeYdb: unknown table "${table}"`);

      const conditions = this.#parseConditions(whereRaw ?? "", params);
      let rows = store.rows.filter((r) => this.#matches(r, conditions));
      if (offsetRaw) rows = rows.slice(Number(offsetRaw));
      if (limitRaw) rows = rows.slice(0, Number(limitRaw));
      return [rows.map((r) => ({ ...r }))];
    }

    throw new Error(`FakeYdb: unsupported SQL: ${sql}`);
  }

  #parseConditions(
    clause: string,
    params: Record<string, unknown>,
  ): Array<{ col: string; op: string; value: unknown }> {
    const out: Array<{ col: string; op: string; value: unknown }> = [];
    for (const [, col, name] of clause.matchAll(/`(\w+)` = \$(\w+)/g)) {
      out.push({ col, op: "=", value: params[name] });
    }
    for (const [, col] of clause.matchAll(/`(\w+)` IS NOT NULL/g)) {
      out.push({ col, op: "IS NOT NULL", value: undefined });
    }
    for (const [, col] of clause.matchAll(/`(\w+)` IS NULL/g)) {
      out.push({ col, op: "IS NULL", value: undefined });
    }
    return out;
  }

  #matches(
    row: Record<string, any>,
    conditions: Array<{
      col: string;
      op: string;
      value: unknown;
    }>,
  ): boolean {
    return conditions.every(({ col, op, value }) => {
      if (op === "=") {
        const rv = row[col];
        const lv = value;
        if (rv instanceof Uint8Array && lv instanceof Uint8Array) {
          return Buffer.compare(Buffer.from(rv), Buffer.from(lv)) === 0;
        }
        return String(rv) === String(lv);
      }
      if (op === "IS NULL") return row[col] === null || row[col] === undefined;
      if (op === "IS NOT NULL")
        return !(row[col] === null || row[col] === undefined);
      return false;
    });
  }
}

// ─────────────────────────────────────────────────────────────
// Mock Yandex KMS API (base64 — только внутри адаптера)
// ─────────────────────────────────────────────────────────────

function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}

function kmsJsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

function kmsErrorResponse(status: number, body: string): Response {
  return {
    ok: false,
    status,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(body),
  } as Response;
}

/**
 * Эмуляция SymmetricCrypto encrypt/decrypt: хранит соответствие
 * base64(ciphertext) → { plaintext, aad }. Decrypt без правильного
 * AAD завершается ошибкой — как в реальном KMS.
 */
function createMockKms(keyId: string) {
  interface Record_ {
    plaintextB64: string;
    aadB64: string;
  }
  const store = new Map<string, Record_>();
  const requests: Array<{ url: string; body: any }> = [];

  const fetchMock = jest.fn(
    (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const body = JSON.parse(init!.body as string);
      const urlText =
        typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
      requests.push({ url: urlText, body });

      if (urlText.includes(":encrypt")) {
        const ciphertextB64 = randomBytes(48).toString("base64");
        store.set(ciphertextB64, {
          plaintextB64: body.plaintext,
          aadB64: body.aadContext ?? "",
        });
        return Promise.resolve(
          kmsJsonResponse({
            keyId,
            versionId: "v1",
            ciphertext: ciphertextB64,
          }),
        );
      }

      if (urlText.includes(":decrypt")) {
        const record = store.get(body.ciphertext);
        if (!record || record.aadB64 !== (body.aadContext ?? "")) {
          return Promise.resolve(
            kmsErrorResponse(400, "Invalid ciphertext or AAD mismatch"),
          );
        }
        return Promise.resolve(
          kmsJsonResponse({
            keyId,
            versionId: "v1",
            plaintext: record.plaintextB64,
          }),
        );
      }

      return Promise.resolve(kmsErrorResponse(404, "Not found"));
    },
  );

  return { fetchMock, requests, store };
}

// ─────────────────────────────────────────────────────────────
// Тестовая сущность (@YdbSecurityAAD на PK — привязка шифротекста к строке)
// ─────────────────────────────────────────────────────────────

@YdbEntity("kms_pipeline_users")
class PipelineUserEntity extends YdbBaseEntity {
  @YdbPrimaryColumn("Uuid")
  @YdbSecurityAAD()
  uuid!: string;

  @YdbEncrypted({ blindIndex: true })
  email!: string;

  @YdbEncrypted({ blindIndex: false })
  notes!: string;

  @YdbColumn("Utf8")
  plain!: string;
}

// ─────────────────────────────────────────────────────────────
// Suite
// ─────────────────────────────────────────────────────────────

const originalFetch = globalThis.fetch;
const BI_KEY = Buffer.alloc(32, 7).toString("base64");

let db: FakeYdb;
let kms: ReturnType<typeof createMockKms>;
let enc: KmsEncryptionProvider;
let bi: KmsBlindIndexProvider;

beforeAll(() => {
  db = new FakeYdb();
  db.registerTable("kms_pipeline_users", ["uuid"]);
  kms = createMockKms("pipeline-key");
  globalThis.fetch = kms.fetchMock;

  enc = new KmsEncryptionProvider({
    keyId: "pipeline-key",
    auth_type: "iam_token",
    authOptions: { iam_token: "test-token" },
  });
  bi = new KmsBlindIndexProvider({ blindIndexKey: BI_KEY });

  configureEntities([PipelineUserEntity], {
    executor: db.executor(),
    encryptionProvider: enc,
    blindIndexProvider: bi,
  });
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe("ORM pipeline × KMS providers (real @ycforge/ydb-orm interface)", () => {
  it("save() stores raw Uint8Array ciphertext + blind index; find() decrypts", async () => {
    const user = new PipelineUserEntity();
    user.email = "alice@example.com";
    user.notes = "private note";
    user.plain = "not encrypted";

    await PipelineUserEntity.save(user);
    expect(user.uuid).toBeTruthy();

    // В «БД» — raw Bytes, а не base64-строка
    const stored = db.rows("kms_pipeline_users")[0];
    expect(stored.uuid).toBe(user.uuid);
    expect(stored.email).toBeInstanceOf(Uint8Array);
    expect(stored.notes).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(stored.email).toString("utf8")).not.toBe(
      "alice@example.com",
    );
    expect(typeof stored.email_bi).toBe("string");

    // Blind index совпадает с прямым вызовом провайдера
    expect(stored.email_bi).toBe(await bi.hash("alice@example.com", {} as any));

    // Чтение через ORM дешифрует
    const found = await PipelineUserEntity.find({ uuid: user.uuid });
    expect(found).not.toBeNull();
    expect(found!.email).toBe("alice@example.com");
    expect(found!.notes).toBe("private note");
    expect(found!.plain).toBe("not encrypted");
  });

  it("find() by encrypted field goes through blind index", async () => {
    const user = new PipelineUserEntity();
    user.email = "bob@example.com";
    user.notes = "";
    user.plain = "";

    await PipelineUserEntity.save(user);

    const found = await PipelineUserEntity.find({
      email: "bob@example.com",
    });
    expect(found).not.toBeNull();
    expect(found!.uuid).toBe(user.uuid);

    // Другое значение не находится
    const miss = await PipelineUserEntity.find({
      email: "other@example.com",
    });
    expect(miss).toBeNull();

    // Поиск по зашифрованному полю без blind index запрещён ORM
    await expect(
      PipelineUserEntity.find({ notes: "x" } as any),
    ).rejects.toThrow(/blind index/i);
  });

  it("AAD binding: KMS receives aadContext from @YdbSecurityAAD field", async () => {
    const user = new PipelineUserEntity();
    user.email = "carol@example.com";
    user.notes = "aad-note";
    user.plain = "";

    await PipelineUserEntity.save(user);

    const expectedAad = b64(`uuid=${user.uuid}`);
    const encryptCalls = kms.requests.filter((r) => r.url.includes(":encrypt"));
    const lastTwo = encryptCalls.slice(-2); // email + notes
    for (const call of lastTwo) {
      expect(call.body.aadContext).toBe(expectedAad);
    }

    // Расшифровка с тем же AAD работает…
    const stored = db
      .rows("kms_pipeline_users")
      .find((r) => r.uuid === user.uuid)!;
    const decrypted = await enc.decrypt(stored.email, `uuid=${user.uuid}`, {
      entityName: "PipelineUserEntity",
      tableName: "kms_pipeline_users",
      fieldName: "email",
      primaryKeyValue: user.uuid,
      aadFields: { uuid: user.uuid },
    });
    expect(decrypted).toBe("carol@example.com");

    // …а с чужим AAD KMS отвергает ciphertext
    await expect(
      enc.decrypt(stored.email, "uuid=00000000-0000-5000-8000-000000000000", {
        entityName: "PipelineUserEntity",
        tableName: "kms_pipeline_users",
        fieldName: "email",
        primaryKeyValue: "00000000-0000-5000-8000-000000000000",
        aadFields: {},
      }),
    ).rejects.toThrow(/KMS decrypt failed: 400/);
  });

  it("encrypted updateBy(): re-encrypts, updates blind index, old value unsearchable", async () => {
    const user = new PipelineUserEntity();
    user.email = "old@example.com";
    user.notes = "old-notes";
    user.plain = "";

    await PipelineUserEntity.save(user);

    const updated = await PipelineUserEntity.updateBy(
      { uuid: user.uuid },
      { email: "new@example.com", notes: "new-notes" },
    );
    expect(updated).toBe(1);

    // Шифротекст заменён на новый (Uint8Array)
    const stored = db
      .rows("kms_pipeline_users")
      .find((r) => r.uuid === user.uuid)!;
    expect(stored.email).toBeInstanceOf(Uint8Array);

    // Поиск по старому значению не находит, по новому — находит
    const oldRow = await PipelineUserEntity.find({ email: "old@example.com" });
    expect(oldRow).toBeNull();

    const newRow = await PipelineUserEntity.find({ email: "new@example.com" });
    expect(newRow).not.toBeNull();
    expect(newRow!.notes).toBe("new-notes");
    expect(newRow!.email).toBe("new@example.com");

    // Blind index обновлён
    expect(stored.email_bi).toBe(await bi.hash("new@example.com", {} as any));
  });

  it("save() on existing row (update path) re-encrypts changed fields", async () => {
    const user = new PipelineUserEntity();
    user.email = "update-path-old@example.com";
    user.notes = "v1";
    user.plain = "";

    await PipelineUserEntity.save(user);

    const emailBefore = db
      .rows("kms_pipeline_users")
      .find((r) => r.uuid === user.uuid)!.email;

    user.email = "update-path-new@example.com";
    user.notes = "v2";
    const saved = await PipelineUserEntity.save(user);

    expect(saved.uuid).toBe(user.uuid);
    expect(saved.email).toBe("update-path-new@example.com");

    const stored = db
      .rows("kms_pipeline_users")
      .find((r) => r.uuid === user.uuid)!;
    expect(
      Buffer.compare(Buffer.from(stored.email), Buffer.from(emailBefore)),
    ).not.toBe(0);
    expect(stored.email_bi).toBe(
      await bi.hash("update-path-new@example.com", {} as any),
    );

    const found = await PipelineUserEntity.find({ uuid: user.uuid });
    expect(found!.email).toBe("update-path-new@example.com");
    expect(found!.notes).toBe("v2");
  });

  it("roundtrip keeps binary-safe ciphertext (Uint8Array in → Uint8Array out)", async () => {
    const user = new PipelineUserEntity();
    user.email = "bin@example.com";
    user.notes = "юникод 🌍 значение";
    user.plain = "";

    await PipelineUserEntity.save(user);

    const stored = db
      .rows("kms_pipeline_users")
      .find((r) => r.uuid === user.uuid)!;

    // ciphertext — произвольные бинарные данные, переживают base64-границу KMS
    expect(stored.notes).toBeInstanceOf(Uint8Array);
    expect(stored.notes.length).toBeGreaterThan(0);

    const decrypted = await enc.decrypt(
      stored.notes,
      `uuid=${user.uuid}`,
      {} as any,
    );
    expect(decrypted).toBe("юникод 🌍 значение");

    const found = await PipelineUserEntity.find({ uuid: user.uuid });
    expect(found!.notes).toBe("юникод 🌍 значение");
  });
});
