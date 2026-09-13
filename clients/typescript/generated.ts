/** Generated TypeScript client; do not edit by hand.
 *
 * Rendered from the shared component manifest and OpenAPI operation projection.
 */
export const PROTOCOL = "workspace.v1" as const;
export const GENERATOR = "GENERATOR-TYPESCRIPT-CONFORMANCE" as const;
export const COMPONENT_MANIFEST_SHA256 = "dc91a45390f33582f0299f81285d165128e1885a9fd62b4ccffa7b8e465ed63a" as const;
export const CONTRACT_SHA256 = "a5937eed6e7413ce15489d9ec91d22d0994a94a3d62b1a5470e9a31aa4a7d7af" as const;
export const SCHEMA_MANIFEST_SHA256 = "50747fa5bbddd72438599c87c2716b8b3b65f1a1eb26a2f3b295d1f838de2c07" as const;
export const OPERATIONS = ["addShotItem","admitTask","adoptManagedOutput","archiveProjectReference","archiveProjectShot","archiveReference","archiveShot","archiveTimeline","associateReference","cancelRun","cancelTask","checkpointAttempt","claimTask","createBackup","createDocument","createGeneration","createMediaRelation","createProject","createProjectReference","createProjectShot","createReference","createShot","createTimeline","createTimelineDocument","createVariant","currentProject","diffTimeline","doctor","exportRealm","failAttempt","getDocument","getGeneration","getManagedOutput","getObject","getProject","getProjectReference","getProjectShot","getProjectShotTextBinding","getRealm","getReference","getRun","getShot","getTask","getTimeline","getVariant","handshake","headObject","health","heartbeatAttempt","ingestObject","ingestProjectObject","linkReferences","listCapabilities","listDocuments","listEvents","listGenerations","listManagedOutputs","listMediaRelations","listProjectObjects","listProjectReferences","listProjectRuns","listProjectShotTextBindings","listProjectShots","listProjectTasks","listProjects","listRunEvents","listTimelineHistory","listTimelines","listVariants","prepareReboot","promoteProjectShotCandidate","publishTimelineRender","purgeRealm","rebindProjectShotTextBinding","recoverProjectReference","recoverProjectShot","recoverRealm","recoverReference","recoverShot","recoverTimeline","registerCapability","registerExecutor","removeShotItem","reorderShotItems","replaceTimelineClip","requestReboot","restoreBackup","resumeAttempt","retryRun","retryTask","selectProject","setPrimaryReference","setProjectShotTextBinding","setProjectShotTextBindingById","settleAttempt","tombstoneRealm","updateDocument","updateManagedOutputLifecycle","updateProject","updateProjectReference","updateProjectShot","updateReference","updateShot","updateTimeline"] as const;
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
      const responseObject = await fetch(this.baseUrl.replace(/\/$/, "") + path, { method, headers: requestHeaders, body: body as BodyInit | undefined });
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
