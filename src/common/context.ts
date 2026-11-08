import type { YdbEncryptionContext } from '@ycforge/ydb-orm';

function requireText(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !value.length)
    throw new Error(`${name} must be a non-empty string`);
}

/** Canonical domain separation; class names are intentionally not part of identity. */
export function encryptionAad(
  aad: string,
  context: YdbEncryptionContext,
  domain: string,
): string {
  requireText(context?.tableName, 'context.tableName');
  requireText(context?.fieldName, 'context.fieldName');
  requireText(context?.primaryKeyValue, 'context.primaryKeyValue');
  if (typeof aad !== 'string') throw new Error('aad must be a string');
  return JSON.stringify([
    'ycforge:encryption:v1',
    domain,
    context.tableName,
    context.fieldName,
    context.primaryKeyValue,
    aad,
  ]);
}

/** Searchable across records, isolated across table/field/application domains. */
export function blindIndexMessage(
  plaintext: string,
  context: YdbEncryptionContext,
  domain: string,
): string {
  requireText(context?.tableName, 'context.tableName');
  requireText(context?.fieldName, 'context.fieldName');
  if (typeof plaintext !== 'string')
    throw new Error('plaintext must be a string');
  return JSON.stringify([
    'ycforge:blind-index:v1',
    domain,
    context.tableName,
    context.fieldName,
    plaintext,
  ]);
}

export function validateDomain(domain: string): string {
  requireText(domain, 'domain');
  return domain;
}
