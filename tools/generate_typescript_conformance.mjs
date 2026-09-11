#!/usr/bin/env node
/**
 * Generate the checked-in TypeScript conformance client from one contract.
 *
 * The component manifest is a release input, not a second contract.  It binds
 * this output to the same OpenAPI/schema bytes used by the Python generator
 * and carries the canonical wire fixtures.  ``--check`` is deliberately
 * read-only and fails closed on any checked-in source or manifest drift.
 */
import { readFileSync, mkdirSync, writeFileSync, lstatSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { createHash } from "node:crypto";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const GENERATOR = "GENERATOR-TYPESCRIPT-CONFORMANCE";

function argument(name, required = true) {
  const index = process.argv.indexOf(name);
  if (index < 0 || !process.argv[index + 1]) {
    if (required) throw new Error(`${name} is required`);
    return undefined;
  }
  return process.argv[index + 1];
}

function regular(path, label) {
  const target = resolve(path);
  const stat = lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular file`);
  return { path: target, bytes: readFileSync(target) };
}

function sortedValue(value) {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedValue(value[key])]));
  }
  return value;
}

function jsonInput(path, label, canonical = true) {
  const input = regular(path, label);
  let value;
  try {
    value = JSON.parse(input.bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} must be UTF-8 JSON: ${error.message}`);
  }
  const canonicalBytes = `${JSON.stringify(sortedValue(value), null, 2)}\n`;
  if (canonical && input.bytes.toString("utf8") !== canonicalBytes) throw new Error(`${label} must use canonical JSON bytes`);
  return { ...input, value };
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function componentPath(schemaPath, explicit) {
  if (explicit) return resolve(explicit);
  const sibling = join(dirname(schemaPath), "component-manifest.json");
  try {
    regular(sibling, "--component-manifest");
    return sibling;
  } catch {
    throw new Error("--component-manifest is required when no staged sibling manifest exists");
  }
}

function operations(contract) {
  const values = [...contract.toString("utf8").matchAll(/^\s+operationId:\s*([^\s#]+)/gm)].map((match) => match[1]).sort();
  if (!values.length || new Set(values).size !== values.length) throw new Error("--contract has no unique operationId projection");
  return values;
}

function clientDefinition(manifest) {
  if (!Array.isArray(manifest.clients)) throw new Error("component manifest clients must be a list");
  const matches = manifest.clients.filter((item) => item && item.generator === GENERATOR);
  if (matches.length !== 1) throw new Error(`component manifest must declare exactly one ${GENERATOR} client`);
  const client = matches[0];
  for (const key of ["language", "metadata_output", "metadata_source", "output", "source"]) {
    if (typeof client[key] !== "string" || !client[key]) throw new Error(`component manifest ${GENERATOR} client declaration is incomplete`);
  }
  if (client.language !== "typescript") throw new Error(`component manifest ${GENERATOR} language is invalid`);
  return client;
}

function safeRelative(value, label) {
  const target = resolve("/", value);
  if (!value || target !== resolve("/", value) || value.startsWith("/") || value.split("/").includes("..") || value.includes("\\")) {
    throw new Error(`${label} must be a contained relative path`);
  }
  return value;
}

function containedSourcePath(sourceRoot, value, label) {
  const relative = safeRelative(value, label);
  const root = resolve(sourceRoot);
  const candidate = resolve(root, relative);
  let current = root;
  for (const part of relative.split("/")) {
    if (!part || part === ".") continue;
    current = join(current, part);
    try {
      if (lstatSync(current).isSymbolicLink()) throw new Error(`${label} must not traverse a symlink`);
    } catch (error) {
      if (error instanceof Error && error.message === `${label} must not traverse a symlink`) throw error;
      if (error?.code === "ENOENT" || error?.code === "ENOTDIR") break;
      throw error;
    }
  }
  try {
    const resolvedCandidate = realpathSync(candidate);
    if (resolvedCandidate !== root && !resolvedCandidate.startsWith(`${root}/`)) {
      throw new Error(`${label} must be contained by source root`);
    }
  } catch (error) {
    if (error instanceof Error && (error.message === `${label} must be contained by source root` || error.message === `${label} must not traverse a symlink`)) throw error;
    if (error?.code !== "ENOENT" && error?.code !== "ENOTDIR") throw error;
  }
  return candidate;
}

function validateClientSources(sourceRoot, client) {
  return {
    source: containedSourcePath(sourceRoot, client.source, "client source"),
    metadata_source: containedSourcePath(sourceRoot, client.metadata_source, "metadata source"),
  };
}

function validateManifest(manifest, schema) {
  if (manifest.schema_version !== 1 || manifest.manifest_id !== "GENERATOR-CONFORMANCE-ID") throw new Error("component manifest identity is invalid");
  if (manifest.protocol !== "workspace.v1") throw new Error("component manifest protocol is invalid");
  if (!manifest.contract || manifest.contract.openapi !== schema.openapi || manifest.contract.schema_manifest !== "manifest.json") throw new Error("component manifest is not bound to the supplied schema manifest");
  if (schema.protocol !== manifest.protocol) throw new Error("schema manifest protocol does not match component manifest");
  if (!Array.isArray(manifest.fixtures) || !manifest.fixtures.length) throw new Error("component manifest fixtures must be a non-empty list");
  const names = manifest.fixtures.map((item) => item && item.name);
  if (names.some((name) => typeof name !== "string" || !name) || new Set(names).size !== names.length) throw new Error("component manifest fixture names must be unique strings");
  return clientDefinition(manifest);
}

function renderClient(componentDigest, contractDigest, schemaDigest, operationIds) {
  return `/** Generated TypeScript client; do not edit by hand.\n *\n * Rendered from the shared component manifest and OpenAPI operation projection.\n */
export const PROTOCOL = "workspace.v1" as const;
export const GENERATOR = "${GENERATOR}" as const;
export const COMPONENT_MANIFEST_SHA256 = "${componentDigest}" as const;
export const CONTRACT_SHA256 = "${contractDigest}" as const;
export const SCHEMA_MANIFEST_SHA256 = "${schemaDigest}" as const;
export const OPERATIONS = ${JSON.stringify(operationIds)} as const;
export type HeadersLike = Record<string, string>;
export type Transport = (method: string, path: string, headers: HeadersLike, body?: Uint8Array) => Promise<{ status: number; headers: HeadersLike; body: Uint8Array }>;
export type ManagedOutputDurability = "durable" | "temporary";
export type ManagedCoverageMode = "interval" | "clips" | "cuts" | "shots";
export interface ManagedOutput {
  association_id: string;
  project_id: string | null;
  run_id: string;
  task_id: string;
  attempt_id: string;
  output_port: string;
  group_key: string;
  variant_key: string;
  selector: { group_key: string; variant_key: string };
  object_id: string;
  digest: string;
  manifest_ref: string | null;
  size: number;
  filename: string;
  media_type: string;
  ordinal: number;
  role: string;
  producer: Record<string, unknown>;
  provenance: Record<string, unknown>;
  durability: ManagedOutputDurability;
  regeneration?: Record<string, unknown> | null;
  coverage?: Record<string, unknown> | null;
  state: string;
  version: number;
  lifecycle: Record<string, unknown>;
  [key: string]: unknown;
}
export interface ManagedOutputPage { items: ManagedOutput[]; next_cursor: string | null; }
export interface ManagedOutputAdoption { association_id?: string; manifest_ref?: string | null; object_id?: string; digest?: string; size?: number; filename?: string; media_type?: string; output_port?: string; selector?: Record<string, unknown>; ordinal?: number; role?: string; durability?: ManagedOutputDurability; }
export interface ManagedOutputLifecycle { operation: "lease" | "release" | "pin" | "unpin" | "expire" | "reclaim" | "promote"; expected_version: number; lease_id?: string; lease_owner?: string; lease_seconds?: number; provenance?: Record<string, unknown>; }
export type MutationResult<T> = T & { readonly receipt: Record<string, unknown> };

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public request_id = "", public details: Record<string, unknown> = {}) {
    super(code + ": " + message);
    this.name = "ApiError";
  }
}

export class WorkspaceClient {
  constructor(private readonly baseUrl: string, private readonly token?: string, private readonly transport?: Transport) {}

  supports(operationId: string): boolean { return (OPERATIONS as readonly string[]).includes(operationId); }

  async call(operationId: string, method: string, path: string, body?: Uint8Array, headers: HeadersLike = {}, expected: number[] = [200]): Promise<{ status: number; headers: HeadersLike; body: Uint8Array }> {
    if (!this.supports(operationId)) throw new Error("unknown workspace operation: " + operationId);
    const requestHeaders: HeadersLike = { Accept: "application/json", ...headers };
    if (this.token) requestHeaders.Authorization ??= "Bearer " + this.token;
    let response: { status: number; headers: HeadersLike; body: Uint8Array };
    if (this.transport) response = await this.transport(method, path, requestHeaders, body);
    else {
      const responseObject = await fetch(this.baseUrl.replace(/\\/$/, "") + path, { method, headers: requestHeaders, body: body as BodyInit | undefined });
      const responseHeaders: HeadersLike = {};
      responseObject.headers.forEach((value, key) => { responseHeaders[key] = value; });
      response = { status: responseObject.status, headers: responseHeaders, body: new Uint8Array(await responseObject.arrayBuffer()) };
    }
    if (!expected.includes(response.status)) {
      let value: Record<string, unknown> = {};
      try { value = JSON.parse(new TextDecoder().decode(response.body)) as Record<string, unknown>; } catch { /* non-JSON error */ }
      throw new ApiError(response.status, String(value.code ?? "http_error"), String(value.message ?? ("HTTP " + response.status)), String(value.request_id ?? ""), (value.details ?? {}) as Record<string, unknown>);
    }
    return response;
  }

  private json<T>(body: Uint8Array): T { return JSON.parse(new TextDecoder().decode(body)) as T; }
  private page<T>(body: Uint8Array): { items: T[]; next_cursor: string | null } {
    const value = this.json<{ items: T[]; next_cursor: string | null }>(body);
    if (!Array.isArray(value.items) || (value.next_cursor !== null && typeof value.next_cursor !== "string")) throw new Error("invalid page response");
    return value;
  }
  private mutation<T>(body: Uint8Array): MutationResult<T> {
    const value = this.json<{ data?: T; receipt?: Record<string, unknown> }>(body);
    if (!value.data || !value.receipt) throw new Error("invalid mutation response: committed receipt is required");
    return Object.assign(value.data, { receipt: value.receipt }) as MutationResult<T>;
  }
  async listManagedOutputs(taskId: string, cursor?: string, limit = 50): Promise<ManagedOutputPage> {
    const query = "?limit=" + limit + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "");
    return this.page<ManagedOutput>(
      (await this.call("listManagedOutputs", "GET", "/v1/tasks/" + encodeURIComponent(taskId) + "/managed-outputs" + query)).body,
    );
  }
  async getManagedOutput(associationId: string): Promise<ManagedOutput> {
    return this.json<ManagedOutput>((await this.call("getManagedOutput", "GET", "/v1/managed-outputs/" + encodeURIComponent(associationId))).body);
  }
  async adoptManagedOutput(associationId: string, idempotencyKey: string, body: ManagedOutputAdoption = {}): Promise<MutationResult<ManagedOutput>> {
    return this.mutation<ManagedOutput>((await this.call("adoptManagedOutput", "POST", "/v1/managed-outputs/" + encodeURIComponent(associationId) + "/adopt", new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body);
  }
  async updateManagedOutputLifecycle(associationId: string, body: ManagedOutputLifecycle, idempotencyKey: string): Promise<MutationResult<ManagedOutput>> {
    return this.mutation<ManagedOutput>((await this.call("updateManagedOutputLifecycle", "POST", "/v1/managed-outputs/" + encodeURIComponent(associationId) + "/lifecycle", new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body);
  }
}
`;
}

function renderMetadata(componentDigest, contractDigest, schemaDigest, operationIds) {
  return `/** Generated TypeScript client metadata; do not edit by hand. */
export const GENERATOR = "${GENERATOR}" as const;
export const PROTOCOL = "workspace.v1" as const;
export const COMPONENT_MANIFEST_SHA256 = "${componentDigest}" as const;
export const CONTRACT_SHA256 = "${contractDigest}" as const;
export const SCHEMA_MANIFEST_SHA256 = "${schemaDigest}" as const;
export const OPERATIONS = ${JSON.stringify(operationIds)} as const;
`;
}

function fixtureBytes(manifest) {
  const result = {};
  for (const item of [...manifest.fixtures].sort((a, b) => a.name.localeCompare(b.name))) {
    const name = safeRelative(item.name, "fixture name");
    if (!item.value || typeof item.value !== "object" || Array.isArray(item.value)) throw new Error(`fixture ${name} must contain an object value`);
    result[`fixture-${name}`] = Buffer.from(`${JSON.stringify(sortedValue(item.value))}\n`, "utf8");
  }
  return result;
}

function renderFiles(manifest, componentBytes, contract, schemaBytes) {
  const client = clientDefinition(manifest);
  const componentDigest = digest(componentBytes);
  const contractDigest = digest(contract);
  const schemaDigest = digest(schemaBytes);
  const operationIds = operations(contract);
  const files = {
    [safeRelative(client.output, "client output")]: Buffer.from(renderClient(componentDigest, contractDigest, schemaDigest, operationIds), "utf8"),
    [safeRelative(client.metadata_output, "metadata output")]: Buffer.from(renderMetadata(componentDigest, contractDigest, schemaDigest, operationIds), "utf8"),
    ...fixtureBytes(manifest),
    "component-manifest.json": componentBytes,
  };
  const artifacts = Object.entries(files).filter(([path]) => path !== "component-manifest.json").map(([path, data]) => ({ byte_length: data.length, path, sha256: digest(data) })).sort((a, b) => a.path.localeCompare(b.path));
  files["manifest.json"] = Buffer.from(`${JSON.stringify(sortedValue({
    artifacts,
    component_manifest_id: manifest.manifest_id,
    component_manifest_sha256: componentDigest,
    contract_sha256: contractDigest,
    generator: GENERATOR,
    operations: operationIds,
    protocol: manifest.protocol,
    schema_manifest_sha256: schemaDigest,
    schema_version: 1,
  }), null, 2)}\n`, "utf8");
  return files;
}

function writeFiles(root, files) {
  mkdirSync(root, { recursive: true });
  for (const [relative, data] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) {
    const target = resolve(root, relative);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, data);
  }
}

function checkFiles(sourceRoot, files, client, fixtureRoot, sourcePaths) {
  const checks = {
    [sourcePaths.source]: files[safeRelative(client.output, "client output")],
    [sourcePaths.metadata_source]: files[safeRelative(client.metadata_output, "metadata output")],
  };
  if (fixtureRoot) {
    for (const [relative, data] of Object.entries(files)) if (relative.startsWith("fixture-")) checks[resolve(fixtureRoot, relative.slice("fixture-".length))] = data;
  }
  const failures = [];
  for (const [target, expected] of Object.entries(checks)) {
    try {
      const actual = regular(target, "generated artifact").bytes;
      if (!actual.equals(expected)) failures.push(target);
    } catch {
      failures.push(target);
    }
  }
  for (const target of failures) console.error(`stale or mutated generated artifact: ${target}`);
  return failures.length ? 1 : 0;
}

function main() {
  const contractInput = regular(argument("--contract"), "--contract");
  const schemaInput = jsonInput(argument("--schema-manifest"), "--schema-manifest", false);
  const componentInput = jsonInput(componentPath(schemaInput.path, argument("--component-manifest", false)), "--component-manifest");
  const client = validateManifest(componentInput.value, schemaInput.value);
  const sourceRoot = resolve(argument("--source-root", false) ?? ROOT);
  const sourcePaths = validateClientSources(sourceRoot, client);
  const files = renderFiles(componentInput.value, componentInput.bytes, contractInput.bytes, schemaInput.bytes);
  const fixtureRoot = argument("--fixture-root", false);
  if (process.argv.includes("--check")) return checkFiles(sourceRoot, files, client, fixtureRoot ? resolve(fixtureRoot) : undefined, sourcePaths);
  const outputRoot = argument("--output-root");
  writeFiles(resolve(outputRoot), files);
  for (const relative of Object.keys(files).sort()) console.log(relative);
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
