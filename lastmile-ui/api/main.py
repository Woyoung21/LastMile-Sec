"""LastMile pipeline JSON sidecar — reads only under DATA_ROOT (default /app/data)."""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

DATA_ROOT = os.path.abspath(os.environ.get("LASTMILE_DATA_DIR", "/app/data"))
ALLOWED_FOLDERS = frozenset({"processed", "mapped", "correlate", "remediated"})

app = FastAPI(title="LastMile Sidecar", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _safe_subdir(folder: str) -> str:
    if folder not in ALLOWED_FOLDERS:
        raise HTTPException(status_code=400, detail="invalid folder name")
    base = os.path.abspath(os.path.join(DATA_ROOT, folder))
    data_root = os.path.abspath(DATA_ROOT)
    prefix = data_root if data_root.endswith(os.sep) else data_root + os.sep
    if base != data_root and not base.startswith(prefix):
        raise HTTPException(status_code=400, detail="invalid path")
    return base


def _resolve_file(folder: str, filename: str) -> str:
    base = _safe_subdir(folder)
    safe_name = os.path.basename(filename)
    if not safe_name.endswith(".json"):
        raise HTTPException(status_code=400, detail="only .json files allowed")
    path = os.path.normpath(os.path.join(base, safe_name))
    try:
        common = os.path.commonpath([os.path.normpath(base), path])
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid path")
    if os.path.normcase(common) != os.path.normcase(os.path.normpath(base)):
        raise HTTPException(status_code=400, detail="path traversal")
    return path


def _list_json_files(folder: str) -> list[str]:
    base = _safe_subdir(folder)
    if not os.path.isdir(base):
        return []
    return sorted(f for f in os.listdir(base) if f.endswith(".json"))


def _read_json_path(path: str) -> dict[str, Any]:
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="file not found")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _latest_path(folder: str) -> str | None:
    base = _safe_subdir(folder)
    names = _list_json_files(folder)
    if not names:
        return None
    paths = [os.path.join(base, n) for n in names]
    return max(paths, key=lambda p: os.path.getmtime(p))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "data_root": DATA_ROOT}


@app.get("/api/inventory/{folder}")
def inventory(folder: str) -> dict[str, Any]:
    if folder not in ALLOWED_FOLDERS:
        raise HTTPException(status_code=400, detail="invalid folder")
    base = _safe_subdir(folder)
    files = _list_json_files(folder)
    return {
        "folder": folder,
        "path": base,
        "files": files,
        "exists": os.path.isdir(base),
    }


@app.get("/api/latest")
def latest_packet(
    folder: str = Query(
        ...,
        pattern="^(processed|mapped|correlate|remediated)$",
    ),
) -> dict[str, Any]:
    path = _latest_path(folder)
    if path is None:
        raise HTTPException(status_code=404, detail="no json files in folder")
    name = os.path.basename(path)
    body = _read_json_path(path)
    return {"filename": name, "path": path.replace("\\", "/"), "data": body}


@app.get("/api/file")
def file_by_name(
    folder: str = Query(..., pattern="^(processed|mapped|correlate|remediated)$"),
    name: str = Query(..., description="JSON filename in folder"),
) -> dict[str, Any]:
    path = _resolve_file(folder, name)
    body = _read_json_path(path)
    return {"filename": os.path.basename(path), "data": body}
