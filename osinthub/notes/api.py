"""Notes API. Reference: okf/architecture/notes.md

GET    /api/notes?kind=&item=        the notes of one item (oldest first)
GET    /api/notes?q=&kind=&limit=    all notes, newest change first (the Notes list)
GET    /api/notes/counts             {kind: {item: n}} for the badges in lists
POST   /api/notes                    {kind, item, body, title?}
PUT    /api/notes/{id}               {body?, title?}
DELETE /api/notes/{id}
POST   /api/notes/import             {notes: [{kind, item, body, title?}]}: the old browser notes, once
POST   /api/notes/redact             {text}: home addresses, MACs and device names replaced
"""
from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query

from . import store

router = APIRouter(prefix="/api/notes", tags=["notes"])


@router.get("")
def list_notes(kind: str | None = None, item: str | None = None, q: str = "",
               limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)):
    try:
        if item is not None:
            return {"notes": store.for_item(kind, item)}
        return store.search(q, kind or None, limit, offset)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/counts")
def note_counts(kind: str | None = None):
    if kind and kind not in store.KINDS:
        raise HTTPException(400, f"kind must be one of {', '.join(store.KINDS)}")
    return store.counts(kind)


@router.post("")
def create_note(body: dict = Body(...)):
    try:
        return store.create(body.get("kind"), body.get("item"), body.get("body"), body.get("title"))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.put("/{nid}")
def update_note(nid: str, body: dict = Body(...)):
    try:
        return store.update(nid, body.get("body"), body.get("title"))
    except KeyError:
        raise HTTPException(404, "no such note")
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/{nid}")
def delete_note(nid: str):
    if not store.delete(nid):
        raise HTTPException(404, "no such note")
    return {"ok": True}


@router.post("/import")
def import_notes(body: dict = Body(...)):
    notes = body.get("notes")
    if not isinstance(notes, list) or len(notes) > 5000:
        raise HTTPException(400, "notes must be a list of at most 5000 notes")
    return store.import_notes(notes)


@router.post("/redact")
def redact(body: dict = Body(...)):
    text = body.get("text")
    if not isinstance(text, str) or len(text) > 500_000:
        raise HTTPException(400, "text must be a string of at most 500,000 characters")
    return store.redact(text)
