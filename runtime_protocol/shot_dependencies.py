"""Deterministic invalidation analysis for shot-owned media descriptors.

The runtime stores the report in the promotion receipt.  This module is
intentionally pure so the same bytes are produced on a retry and the runtime
does not need to invent product-specific queue state.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_DETERMINISTIC = frozenset({"plate", "render_plate", "proxy", "review_proxy", "timeline_asset"})
_GENERATIVE = frozenset({"transition", "generative_transition", "continuity", "continuity_input"})


def _records(value: object) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [item for item in value.values() if isinstance(item, Mapping)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _meta(record: Mapping[str, Any]) -> Mapping[str, Any]:
    value = record.get("metadata")
    return value if isinstance(value, Mapping) else record


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _kind(record: Mapping[str, Any]) -> str:
    metadata = _meta(record)
    return str(metadata.get("kind") or metadata.get("item_kind") or metadata.get("dependency_kind") or metadata.get("role") or "").lower()


def _descriptor(record: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _meta(record)
    return {
        "source_item_id": _string(metadata.get("source_item_id") or metadata.get("source_item")),
        "source_media_id": _string(metadata.get("source_media_id") or metadata.get("source_media") or metadata.get("input_media_id")),
        "source_content_sha256": _string(metadata.get("source_content_sha256") or metadata.get("source_hash") or metadata.get("source_content_hash") or metadata.get("input_content_sha256")),
    }


def _endpoint_mismatch(record: Mapping[str, Any], media_hashes: Mapping[str, str], superseded: set[str], active_media: str | None) -> tuple[str, str, str] | None:
    metadata = _meta(record)
    for endpoint in ("from", "to", "start", "end", "parent", "input"):
        media_id = _string(metadata.get(f"{endpoint}_media_id") or metadata.get(f"{endpoint}_media"))
        expected = _string(metadata.get(f"{endpoint}_content_sha256") or metadata.get(f"{endpoint}_content_hash") or metadata.get(f"{endpoint}_hash"))
        if media_id is None:
            continue
        if media_id in superseded and active_media is not None:
            return (f"{endpoint}_media_id", media_id, active_media)
        if expected is not None and media_hashes.get(media_id) != expected:
            return (f"{endpoint}_content_sha256", expected, str(media_hashes.get(media_id)))
    return None


def _mismatch(descriptor: Mapping[str, Any], active_item: str | None, item_by_id: Mapping[str, Mapping[str, Any]], stale: set[str], media_hashes: Mapping[str, str]) -> tuple[str, str, str] | None:
    expected_item = descriptor.get("source_item_id")
    expected_media = descriptor.get("source_media_id")
    expected_hash = descriptor.get("source_content_sha256")
    if expected_item is not None:
        source = item_by_id.get(str(expected_item))
        if source is None:
            return ("source_item_id", str(expected_item), "missing")
        if str(expected_item) in stale:
            return ("source_item_id", str(expected_item), "stale")
        if _kind(source) == "primary_visual" and active_item is not None and str(expected_item) != active_item:
            return ("source_item_id", str(expected_item), active_item)
    if expected_media is not None and expected_hash is not None and media_hashes.get(str(expected_media)) != expected_hash:
        return ("source_content_sha256", str(expected_hash), str(media_hashes.get(str(expected_media))))
    return None


def _entry(record: Mapping[str, Any], reason: str, mismatch: tuple[str, str, str]) -> dict[str, Any]:
    field, expected, actual = mismatch
    result: dict[str, Any] = {"kind": _kind(record), "reason": reason, "field": field, "expected": expected, "actual": actual}
    item_id = _string(record.get("id") or record.get("item_id"))
    media_id = _string(record.get("media_id"))
    if item_id is not None: result["item_id"] = item_id
    if media_id is not None: result["media_id"] = media_id
    return result


def analyze_invalidation(shot_items: object = (), media: object = (), timeline_assets: object = (), *, media_relations: object = ()) -> dict[str, list[dict[str, Any]]]:
    items = _records(shot_items)
    media_records = _records(media)
    relations = _records(media_relations)
    for value in media_records:
        relations.extend(_records(value.get("relations")))
    media_hashes: dict[str, str] = {}
    for value in media_records:
        media_id = _string(value.get("id") or value.get("media_id") or value.get("object_id"))
        content_hash = _string(value.get("content_hash") or value.get("content_sha256") or value.get("digest"))
        if media_id and content_hash: media_hashes[media_id] = content_hash
    item_by_id = {str(item.get("id") or item.get("item_id")): item for item in items if _string(item.get("id") or item.get("item_id"))}
    active_item = next((str(item.get("id") or item.get("item_id")) for item in items if _kind(item) == "primary_visual" and _meta(item).get("status") == "primary"), None)
    active_media = _string(next((item.get("media_id") for item in items if str(item.get("id") or item.get("item_id")) == active_item), None))
    superseded = {_string(item.get("media_id")) for item in items if _kind(item) == "primary_visual" and _meta(item).get("status") == "superseded"}
    superseded.discard(None)
    stale: set[str] = set()
    while True:
        before = len(stale)
        for item in items:
            if _kind(item) not in _DETERMINISTIC: continue
            mismatch = _mismatch(_descriptor(item), active_item, item_by_id, stale, media_hashes) or _endpoint_mismatch(item, media_hashes, superseded, active_media)
            item_id = _string(item.get("id") or item.get("item_id"))
            if mismatch is not None and item_id is not None: stale.add(item_id)
        if len(stale) == before: break
    report: dict[str, list[dict[str, Any]]] = {"stale": [], "blocked_on_generation": [], "ready_to_compile": [], "current": []}
    for item in items:
        kind = _kind(item)
        if kind not in _DETERMINISTIC | _GENERATIVE: continue
        mismatch = _mismatch(_descriptor(item), active_item, item_by_id, stale, media_hashes) or _endpoint_mismatch(item, media_hashes, superseded, active_media)
        if mismatch is None:
            report["current"].append({"kind": kind, "item_id": _string(item.get("id") or item.get("item_id"))})
        else:
            bucket = "stale" if kind in _DETERMINISTIC else "blocked_on_generation"
            report[bucket].append(_entry(item, "frozen deterministic source no longer matches current input" if bucket == "stale" else "generative dependency requires explicit regeneration", mismatch))
    seen: set[tuple[str, str, str, str]] = set()
    for relation in relations:
        if relation.get("kind") != "uses_as_input": continue
        key = (str(relation.get("from_media_id") or relation.get("from_object_id")), str(relation.get("to_media_id") or relation.get("to_object_id")), str(relation.get("kind")), str(relation.get("ordinal")))
        if key in seen: continue
        seen.add(key)
        metadata = relation.get("metadata") if isinstance(relation.get("metadata"), Mapping) else {}
        source_media = _string(metadata.get("source_media_id") or metadata.get("source_media") or relation.get("to_media_id") or relation.get("to_object_id"))
        expected = _string(metadata.get("source_content_sha256") or metadata.get("content_sha256") or metadata.get("content_hash"))
        mismatch = None
        if source_media in superseded and active_media is not None: mismatch = ("source_media_id", str(source_media), active_media)
        elif source_media is not None and expected is not None and media_hashes.get(source_media) != expected: mismatch = ("source_content_sha256", expected, str(media_hashes.get(source_media)))
        if mismatch is not None:
            row = _entry(relation, "continuity input requires explicit regeneration", mismatch)
            row.update({"kind": "continuity_input", "from_media_id": relation.get("from_media_id") or relation.get("from_object_id"), "to_media_id": relation.get("to_media_id") or relation.get("to_object_id")})
            report["blocked_on_generation"].append(row)
    for asset in _records(timeline_assets):
        mismatch = _mismatch(_descriptor(asset), active_item, item_by_id, stale, media_hashes)
        if mismatch is None:
            media_id = _descriptor(asset)["source_media_id"] or _string(asset.get("media_id"))
            expected = _descriptor(asset)["source_content_sha256"] or _string(asset.get("content_sha256") or asset.get("content_hash"))
            if media_id in superseded and active_media is not None: mismatch = ("media_id", str(media_id), active_media)
            elif media_id is not None and expected is not None and media_hashes.get(media_id) != expected: mismatch = ("content_sha256", expected, str(media_hashes.get(media_id)))
        if mismatch is None: report["current"].append({"kind": "timeline_asset", "asset_id": _string(asset.get("id") or asset.get("asset_id"))})
        else:
            row = _entry(asset, "timeline asset pin no longer matches current media", mismatch); row["kind"] = "timeline_asset"; report["stale"].append(row)
            row["asset_id"] = _string(asset.get("id") or asset.get("asset_id"))
    for values in report.values(): values.sort(key=lambda value: (str(value.get("item_id") or value.get("asset_id") or ""), str(value.get("kind"))))
    return report


__all__ = ["analyze_invalidation"]
