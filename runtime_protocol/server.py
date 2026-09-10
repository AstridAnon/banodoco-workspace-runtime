from __future__ import annotations

import json
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit, parse_qs

from .errors import RuntimeErrorBase, AuthorizationError, NotFoundError, ProtocolError, InvalidRequestError
from .service import validate_idempotency_key


class RuntimeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # The default TCPServer backlog is only five. A cold runtime receives a
    # burst of executor/client requests during launch, and an overflow resets
    # otherwise valid loopback connections before the handler can return the
    # durable idempotent replay. Keep a bounded backlog sized for the local
    # control-plane fan-in.
    request_queue_size = 64


class RuntimeHandler(BaseHTTPRequestHandler):
    server_version = "BanodocoRuntime/0.1"
    MAX_BODY_BYTES = 64 * 1024 * 1024
    REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")

    def log_message(self, *_):
        return

    def _request_id(self):
        current = getattr(self, "_runtime_request_id", None)
        if current:
            return current
        supplied = self.headers.get("X-Request-ID", "")
        value = supplied if self.REQUEST_ID_RE.fullmatch(supplied) else uuid.uuid4().hex
        self._runtime_request_id = value
        return value

    @property
    def runtime(self):
        return self.server.runtime  # type: ignore[attr-defined]

    def _identity(self, scope):
        if self.path.split("?", 1)[0] == "/v1/health":
            return {"actor": "health", "scopes": ["health"]}
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            raise AuthorizationError("bearer credential required")
        return self.server.credentials.require(value[7:], scope)  # type: ignore[attr-defined]

    def _content_length(self):
        """Return a strict, bounded request length before touching the body."""
        raw = self.headers.get("Content-Length")
        value = raw.strip() if raw is not None else ""
        if not value or any(char < "0" or char > "9" for char in value):
            raise ProtocolError("Content-Length header is required and must be a non-negative decimal integer")
        length = int(value, 10)
        if length > self.MAX_BODY_BYTES:
            raise ProtocolError("request body exceeds 64 MiB limit")
        return length

    def _raw_body(self):
        length = self._content_length()
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ProtocolError("request body is shorter than Content-Length")
        return raw

    def _body(self):
        raw = self._raw_body()
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("request body must be valid JSON") from exc

    def _project_mutation_body(self):
        body = self._body()
        if not isinstance(body, dict):
            raise InvalidRequestError("request body must be a JSON object")
        return body

    def _idempotency_key(self):
        key = self.headers.get("Idempotency-Key")
        if not key:
            raise ProtocolError("Idempotency-Key header is required")
        try:
            return validate_idempotency_key(key)
        except InvalidRequestError as exc:
            raise ProtocolError(str(exc)) from exc

    def _send(self, status, payload=None, *, headers=None, body=None, error=None, receipt=None, idempotency_key=None):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", self._request_id())
        for key, value in (headers or {}).items():
            self.send_header(key, str(value))
        if body is None:
            encoded = json.dumps(error if error is not None else payload, sort_keys=True).encode()
            self.send_header("Content-Type", "application/json")
        else:
            encoded = body
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _error(self, exc):
        if isinstance(exc, RuntimeErrorBase):
            payload = exc.as_dict()
            payload["request_id"] = self._request_id()
            self._send(exc.status, error=payload)
        else:
            self._send(500, error={"code": "internal_error", "message": "internal runtime error", "request_id": self._request_id()})

    def _route(self):
        path = [unquote(x) for x in urlsplit(self.path).path.split("/") if x]
        method = self.command
        if path == ["v1", "health"]:
            return self._send(200, self.runtime.health())
        if path == ["v1", "credentials"] and method == "POST":
            self._identity("credentials:provision")
            body = self._body()
            actor = str(body.get("actor_id") or "")
            token = str(body.get("credential") or "")
            scope = str(body.get("scope") or "")
            if not actor or not token or scope != "astrid":
                raise ProtocolError("actor_id, credential, and astrid scope are required")
            scopes = ["handshake", "projects:read", "projects:write", "objects:read", "objects:write", "tasks:read", "tasks:write"]
            self.server.credentials.provision_static(actor, token, scopes)  # type: ignore[attr-defined]
            return self._send(201, {"actor_id": actor, "scope": scope})
        if path == ["v1", "handshake"] and method == "POST":
            identity = self._identity("handshake")
            body = self._body()
            body["authenticated_actor"] = identity["actor"]
            body["authenticated_scopes"] = identity.get("scopes", [])
            value = self.runtime.handshake(body)
            return self._send(200, value)
        if path == ["v1", "handshake"] and method == "GET":
            identity = self._identity("handshake")
            return self._send(200, self.runtime.handshake({"authenticated_actor": identity["actor"], "authenticated_scopes": identity.get("scopes", []), "requested_scopes": []}))
        if path == ["v1", "realm"] and method == "GET":
            self._identity("projects:read")
            return self._send(200, self.runtime.realm_resource())
        if path == ["v1", "doctor"] and method == "GET":
            self._identity("admin")
            return self._send(200, self.runtime.doctor())
        if path == ["v1", "realm", "tombstone"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.tombstone(self._body()))
        if path == ["v1", "realm", "recover"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.recover_realm(self._body()))
        if path == ["v1", "realm", "purge"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.purge(self._body()))
        if path == ["v1", "export"] and method == "GET":
            self._identity("admin")
            return self._send(200, self.runtime.export_structured())
        if path == ["v1", "backup"] and method == "POST":
            self._identity("admin")
            body = self._body()
            if not body.get("destination"):
                raise ProtocolError("destination is required")
            return self._send(201, self.runtime.backup(body["destination"]))
        if path == ["v1", "restore"] and method == "POST":
            self._identity("admin")
            body = self._body()
            if not body.get("backup") or not body.get("destination"):
                raise ProtocolError("backup and destination are required")
            return self._send(201, self.runtime.restore(body["backup"], body["destination"]))
        if path == ["v1", "projects", "selection"] and method in ("GET", "PUT"):
            identity = self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                return self._send(200, self.runtime.current_project(identity["actor"]))
            body = self._project_mutation_body()
            if not isinstance(body, dict) or not body.get("project"):
                raise ProtocolError("project is required")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            value = self.runtime.select_project(identity["actor"], body["project"], scope=body.get("scope", "workspace"), idempotency_key=key)
            project_id = value["project"]["project_id"]
            aggregate_id = f"{identity['actor']}:{value['scope']}"
            return self._send(200, {"data": value, "receipt": self.runtime.committed_receipt("project.select", aggregate_id, key, project_id=project_id)})
        if len(path) == 4 and path[:2] == ["v1", "projects"] and path[3] == "timelines":
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "POST":
                body = self._project_mutation_body()
                key = self.headers.get("Idempotency-Key")
                if not key:
                    raise ProtocolError("Idempotency-Key header is required")
                return self._send(201, self.runtime.create_timeline(path[2], body.get("timeline_id", ""), idempotency_key=key))
            if method == "GET":
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.list_timelines(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if len(path) == 4 and path[:2] == ["v1", "projects"] and path[3] == "timeline-documents" and method == "POST":
            self._identity("projects:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(201, self.runtime.create_timeline_document(path[2], self._body(), idempotency_key=key))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("shots", "references") and method == "POST":
            self._identity("projects:write")
            body = self._body()
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(201, self.runtime.create_shot(path[2], body, idempotency_key=key) if path[3] == "shots" else self.runtime.create_reference(path[2], body, idempotency_key=key))
        if len(path) == 3 and path[:2] == ["v1", "timelines"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime._timeline_resource(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "timelines"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_timeline(path[2], self._body(), idempotency_key=self._idempotency_key()))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] == "replace-clip" and method == "POST":
            self._identity("projects:write")
            return self._send(200, self.runtime.replace_timeline_clip(path[2], self._body(), idempotency_key=self._idempotency_key()))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("history", "diff") and method == "GET":
            self._identity("projects:read")
            query = parse_qs(urlsplit(self.path).query)
            if path[3] == "history":
                return self._send(200, self.runtime.list_timeline_history(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
            if "from_version" not in query or "to_version" not in query:
                raise ProtocolError("from_version and to_version are required")
            return self._send(200, self.runtime.diff_timeline(path[2], query["from_version"][0], query["to_version"][0]))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            body = self._body()
            if path[3] == "archive":
                return self._send(200, self.runtime.archive_timeline(path[2], body, idempotency_key=self._idempotency_key()))
            return self._send(200, self.runtime.recover_timeline(path[2], body, idempotency_key=self._idempotency_key()))
        if len(path) == 3 and path[:2] == ["v1", "shots"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_shot(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "shots"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_shot(path[2], self._body(), idempotency_key=self.headers.get("Idempotency-Key")))
        if len(path) == 4 and path[:2] == ["v1", "shots"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(200, self.runtime.archive_shot(path[2], self._body(), idempotency_key=key) if path[3] == "archive" else self.runtime.recover_shot(path[2], self._body(), idempotency_key=key))
        if len(path) == 3 and path[:2] == ["v1", "references"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_reference(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "references"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_reference(path[2], self._body(), idempotency_key=self.headers.get("Idempotency-Key")))
        if len(path) == 4 and path[:2] == ["v1", "references"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(200, self.runtime.archive_reference(path[2], self._body(), idempotency_key=key) if path[3] == "archive" else self.runtime.recover_reference(path[2], self._body(), idempotency_key=key))
        if path == ["v1", "projects"]:
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.list_projects(cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
            if method == "POST":
                body = self._project_mutation_body()
                key = self.headers.get("Idempotency-Key")
                if not key:
                    raise ProtocolError("Idempotency-Key header is required")
                value = self.runtime.create_project(body, idempotency_key=key)
                resource = self.runtime._project_resource(value)
                return self._send(201, {"data": resource, "receipt": self.runtime.committed_receipt("project.create", value["id"], key, project_id=value["id"])})
        if len(path) >= 3 and path[:2] == ["v1", "projects"]:
            selector = path[2]
            if len(path) == 3:
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    return self._send(200, self.runtime._project_resource(self.runtime.get_project(selector)))
                if method == "PATCH":
                    key = self.headers.get("Idempotency-Key")
                    if not key:
                        raise ProtocolError("Idempotency-Key header is required")
                    value = self.runtime.update_project(selector, self._body(), idempotency_key=key)
                    return self._send(200, self.runtime._project_resource(value))
            if len(path) == 4 and path[3] == "documents":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_documents(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
                if method == "POST": return self._send(201, self.runtime.create_document(selector, self._body(), idempotency_key=self._idempotency_key()))
            if len(path) == 5 and path[3] == "documents" and method in ("GET", "PATCH"):
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET": return self._send(200, self.runtime.get_document(selector, path[4]))
                return self._send(200, self.runtime.update_document(selector, path[4], self._body(), idempotency_key=self._idempotency_key()))
            if len(path) == 4 and path[3] == "generations":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_generations(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
                if method == "POST": return self._send(201, self.runtime.create_generation(selector, self._body(), idempotency_key=self._idempotency_key()))
            if len(path) == 4 and path[3] == "objects":
                # Project association is control-plane mutation.  A worker may
                # publish unscoped CAS bytes, but cannot attach arbitrary bytes
                # to a project without the user-scoped project authority.
                self._identity("objects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_project_objects(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
                if method == "POST":
                    key = self._idempotency_key()
                    data = self._raw_body()
                    result = self.runtime.ingest(selector, data, media_type=self.headers.get("Content-Type", "application/octet-stream"), original_name=self.headers.get("X-Original-Name"), expected_digest=self.headers.get("X-Expected-Digest"), idempotency_key=key)
                    return self._send(201, result)
            if len(path) == 4 and path[3] in ("tasks", "runs") and method == "GET":
                self._identity("tasks:read")
                query = parse_qs(urlsplit(self.path).query)
                value = self.runtime.list_project_tasks(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]) if path[3] == "tasks" else self.runtime.list_project_runs(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0])
                return self._send(200, value)
            if len(path) == 4 and path[3] in ("shots", "references") and method == "GET":
                self._identity("projects:read")
                query = parse_qs(urlsplit(self.path).query)
                include_archived = query.get("include_archived", ["false"])[0].lower() == "true"
                value = self.runtime.list_project_shots(selector, cursor=query.get("cursor", [None])[0], include_archived=include_archived, limit=query.get("limit", [50])[0]) if path[3] == "shots" else self.runtime.list_project_references(selector, cursor=query.get("cursor", [None])[0], include_archived=include_archived, limit=query.get("limit", [50])[0])
                return self._send(200, value)
            if len(path) == 4 and path[3] == "shot-text-bindings":
                self._identity("projects:read" if method == "GET" else "projects:write")
                query = parse_qs(urlsplit(self.path).query)
                if method == "GET":
                    return self._send(200, self.runtime.list_project_shot_text_bindings(selector, shot_id=query.get("shot_id", [None])[0], kind=query.get("kind", [None])[0], slot=query.get("slot", [None])[0]))
                if method == "POST":
                    return self._send(200, self.runtime.set_project_shot_text_binding(selector, self._project_mutation_body(), idempotency_key=self._idempotency_key()))
            if len(path) == 5 and path[3] == "shot-text-bindings":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    return self._send(200, self.runtime.get_project_shot_text_binding(selector, path[4]))
                if method == "POST":
                    body = self._project_mutation_body(); body["binding_id"] = path[4]
                    return self._send(200, self.runtime.set_project_shot_text_binding(selector, body, idempotency_key=self._idempotency_key()))
            if len(path) == 6 and path[3] == "shot-text-bindings" and path[5] == "rebind" and method == "POST":
                self._identity("projects:write")
                body = self._project_mutation_body(); body["binding_id"] = path[4]
                return self._send(200, self.runtime.rebind_project_shot_text_binding(selector, body, idempotency_key=self._idempotency_key()))
            if len(path) >= 5 and path[3] in ("shots", "references"):
                kind, resource_id = path[3], path[4]
                self._identity("projects:read" if method == "GET" else "projects:write")
                key = self.headers.get("Idempotency-Key")
                if method == "PATCH" and path[5:] == []:
                    body = self._project_mutation_body()
                    if not key:
                        raise ProtocolError("Idempotency-Key header is required")
                    key = self._idempotency_key()
                    value = self.runtime.update_project_shot(selector, resource_id, body, idempotency_key=key) if kind == "shots" else self.runtime.update_project_reference(selector, resource_id, body, idempotency_key=key)
                    return self._send(200, value)
                if method == "POST" and path[5:] in (["archive"], ["recover"]):
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    value = self.runtime.update_project_shot(selector, resource_id, body, idempotency_key=key, archived=path[5:] == ["archive"]) if kind == "shots" else self.runtime.update_project_reference(selector, resource_id, body, idempotency_key=key, archived=path[5:] == ["archive"])
                    return self._send(200, value)
                if method == "GET" and not path[5:]:
                    return self._send(200, self.runtime.get_project_shot(selector, resource_id) if kind == "shots" else self.runtime.get_project_reference(selector, resource_id))
                if kind == "shots" and path[5:] == ["items"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.add_shot_item(selector, resource_id, body, idempotency_key=key))
                if kind == "shots" and path[5:] == ["promote-candidate"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.promote_project_shot_candidate(selector, resource_id, body, idempotency_key=key))
                if kind == "shots" and len(path) == 7 and path[5] == "items" and method == "DELETE":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.remove_shot_item(selector, resource_id, path[6], body, idempotency_key=key))
                if kind == "shots" and path[5:] == ["reorder"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.reorder_shot_items(selector, resource_id, body, idempotency_key=key))
                if kind == "references" and path[5:] == ["associations"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.associate_reference(selector, resource_id, body, idempotency_key=key))
                if kind == "references" and path[5:] == ["primary"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.set_primary_reference(selector, resource_id, body.get("association_id"), body, idempotency_key=key))
            if len(path) == 4 and path[3] in ("shots", "references") and method == "POST":
                self._identity("projects:write")
                body = self._project_mutation_body()
                key = self.headers.get("Idempotency-Key")
                if not key:
                    raise ProtocolError("Idempotency-Key header is required")
                value = self.runtime.create_project_shot(selector, body, idempotency_key=key) if path[3] == "shots" else self.runtime.create_project_reference(selector, body, idempotency_key=key)
                return self._send(201, value)
            if len(path) == 4 and path[3] == "reference-links" and method == "POST":
                self._identity("projects:write")
                body = self._project_mutation_body()
                key = self.headers.get("Idempotency-Key")
                if not key: raise ProtocolError("Idempotency-Key header is required")
                return self._send(200, self.runtime.link_references(selector, body, idempotency_key=key))
            if len(path) == 4 and path[3] == "media-relations":
                self._identity("objects:read" if method == "GET" else "objects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_media_relations(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
                if method == "POST": return self._send(201, self.runtime.create_media_relation(selector, self._body(), idempotency_key=self._idempotency_key()))
        if path == ["v1", "objects"] and method == "POST":
            self._identity("objects:write")
            key = self._idempotency_key()
            data = self._raw_body()
            value = self.runtime.ingest_object(data, media_type=self.headers.get("Content-Type", "application/octet-stream"), original_name=self.headers.get("X-Filename"), expected_digest=self.headers.get("X-Expected-Digest"), idempotency_key=key)
            return self._send(201, value)
        if len(path) == 3 and path[:2] == ["v1", "objects"] and method in ("GET", "HEAD"):
            self._identity("objects:read")
            metadata, data = self.runtime.object(path[2])
            total = len(data)
            start, end = 0, total - 1
            range_header = self.headers.get("Range")
            status = 200
            if range_header:
                try:
                    unit, spec = range_header.split("=", 1)
                    if unit != "bytes" or "," in spec:
                        raise ValueError
                    left, right = spec.split("-", 1)
                    start = int(left) if left else max(0, total - int(right))
                    end = int(right) if right else total - 1
                    if start < 0 or end < start or end >= total:
                        raise ValueError
                    status = 206
                except ValueError as exc:
                    return self._send(416, {"code": "invalid_range", "message": "invalid byte range"}, headers={"Content-Range": f"bytes */{total}"})
            digest = path[2].removeprefix("sha256:")
            etag_value = "sha256:" + digest
            headers = {"Content-Type": metadata["media_type"], "ETag": f'"{etag_value}"', "Accept-Ranges": "bytes", "X-Content-Digest": etag_value}
            if status == 206:
                headers["Content-Range"] = f"bytes {start}-{end}/{total}"
            return self._send(status, headers=headers, body=data[start:end+1])
        if path == ["v1", "tasks"] and method == "POST":
            self._identity("tasks:write")
            body = self._project_mutation_body()
            body["idempotency_key"] = self.headers.get("Idempotency-Key")
            if not body["idempotency_key"]:
                raise ProtocolError("Idempotency-Key header is required")
            # Admission authority lives here, inside the owner process.  The
            # readiness check and row creation share the store transaction;
            # a client precheck can never race an unavailable registration.
            value = self.runtime.create_task(body, enforce_readiness=True)
            resource = self.runtime._task_resource(value)
            project_id = value["run"].get("project_id") or "unscoped"
            return self._send(201, {"data": resource, "receipt": self.runtime.committed_receipt("task.create", project_id, body.get("idempotency_key"), project_id=project_id)})
        if path == ["v1", "tasks", "claim"] and method == "POST":
            identity = self._identity("worker:execute")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            result = self.runtime.claim_next(self._body(), idempotency_key=key, identity=identity)
            if result is None:
                return self._send(204, body=b"")
            return self._send(200, result)
        if len(path) == 3 and path[:2] == ["v1", "tasks"]:
            task_id = path[2]
            if method == "GET":
                self._identity("tasks:read")
                value = self.runtime.task(task_id)
                return self._send(200, self.runtime._task_resource(value))
        if len(path) == 4 and path[:2] == ["v1", "tasks"]:
            task_id, action = path[2:]
            self._identity("tasks:write")
            if method == "POST" and action == "cancel":
                key = self._idempotency_key()
                value = self.runtime.cancel_task_canonical(task_id, self._body(), idempotency_key=key)
                task = self.runtime.store.get_task(task_id)
                return self._send(200, value)
            if method == "POST" and action == "retry":
                key = self._idempotency_key()
                value = self.runtime.retry_task(task_id, self._body(), idempotency_key=key)
                task = self.runtime.store.get_task(task_id)
                return self._send(200, value)
            if method == "GET" and action == "events":
                task = self.runtime.store.get_task(task_id)
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.events_page(task["run"]["id"], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if len(path) == 4 and path[:2] == ["v1", "attempts"] and method == "POST":
            identity = self._identity("worker:execute")
            action = path[3]
            if action == "prepare-reboot":
                body = self._project_mutation_body()
                # generated clients intentionally do not duplicate it in the
                # JSON body, so bind it at the HTTP boundary before invoking
                # the service.
                body["attempt_id"] = path[2]
                return self._send(200, self.runtime.prepare_reboot(body, identity=identity))
            if action == "checkpoint": return self._send(201, self.runtime.checkpoint_attempt(path[2], self._body(), identity=identity))
            if action == "publish-timeline-render":
                key = self._idempotency_key()
                return self._send(200, self.runtime.publish_timeline_render(path[2], self._body(), idempotency_key=key, identity=identity))
            if action == "settle":
                key = self._idempotency_key()
                value = self.runtime.settle_attempt(path[2], self._body(), idempotency_key=key, identity=identity)
                return self._send(200, value)
            if action == "heartbeat":
                key = self._idempotency_key()
                value = self.runtime.heartbeat_attempt(path[2], self._body(), idempotency_key=key, identity=identity)
                return self._send(200, value)
            if action == "fail":
                key = self._idempotency_key()
                value = self.runtime.fail_attempt(path[2], self._body(), idempotency_key=key, identity=identity)
                return self._send(200, value)
        if path == ["v1", "recovery", "reboot"] and method == "POST":
            identity = self._identity("worker:execute")
            return self._send(200, self.runtime.request_reboot(self._body(), identity=identity))
        if path == ["v1", "recovery", "resume"] and method == "POST":
            identity = self._identity("worker:execute")
            return self._send(200, self.runtime.resume_attempt(self._body(), identity=identity))
        if len(path) == 3 and path[:2] == ["v1", "generations"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_generation(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "generations"] and path[3] == "variants":
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.list_variants(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
            if method == "POST": return self._send(201, self.runtime.create_variant(path[2], self._body(), idempotency_key=self._idempotency_key()))
        if len(path) == 3 and path[:2] == ["v1", "variants"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_variant(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "runs"] and path[3] == "events" and method == "GET":
            self._identity("tasks:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.events_page(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if len(path) == 4 and path[:2] == ["v1", "runs"] and path[3] in ("cancel", "retry") and method == "POST":
            self._identity("tasks:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            body = self._body()
            if path[3] == "cancel":
                return self._send(200, self.runtime.cancel_run(path[2], body, idempotency_key=key))
            return self._send(200, self.runtime.retry_run(path[2], body, idempotency_key=key))
        if path == ["v1", "events"] and method == "GET":
            self._identity("tasks:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.events_page(query.get("aggregate_id", [None])[0], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if path == ["v1", "capabilities"] and method == "GET":
            # Capability discovery is part of task admission, not worker
            # control. Astrid's scoped product actor must be able to resolve
            # a capability digest before creating a task, while registration
            # and execution remain restricted to worker scopes.
            self._identity("tasks:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.list_capabilities(cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if path == ["v1", "capabilities"] and method == "POST":
            self._identity("worker:register")
            return self._send(201, self.runtime.register_capability(self._body()))
        if path == ["v1", "executors"] and method == "POST":
            identity = self._identity("worker:register")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(201, self.runtime.register_executor(self._body(), idempotency_key=key, identity=identity))
        if len(path) == 3 and path[:2] == ["v1", "runs"] and method == "GET":
            self._identity("tasks:read")
            return self._send(200, self.runtime.run(path[2]))
        raise NotFoundError("route not found")

    def _dispatch(self):
        """Serialize handlers that share the daemon's SQLite connection.

        ``ThreadingHTTPServer`` creates one handler thread per request, while
        this runtime intentionally owns one SQLite connection.  The service
        has finer-grained locks around many mutations, but read paths and
        multi-step handlers also touch the connection; the HTTP boundary must
        therefore serialize the complete route.
        """
        try:
            with self.runtime.store._mutex:
                self._route()
        except Exception as exc:
            self._error(exc)

    def do_GET(self):
        self._dispatch()

    def do_HEAD(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_PATCH(self):
        self._dispatch()

    def do_PUT(self):
        self.do_PATCH()

    def do_DELETE(self):
        self._dispatch()
