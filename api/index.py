"""Vercel serverless deployment of the watermarks-remover service.

Matches the local HTTP service contract (service/scripts/server.py):

    GET  /health           -> {"ok": true, "version": ...}
    POST /inspect          -> {"file": <base64>, "name": "x.pdf"}
                           -> {"ok", "kind", "suspicious", "report"}
    POST /clean            -> {"file": <base64>, "name": "x.pdf", "options": {...}}
                           -> {"ok", "kind", "cleaned": <base64>, "report"}

Routing by extension + magic bytes:
    text      -> text_unicode.clean_text (repo module, copied into api/lib/)
    pdf       -> pikepdf: strip /Info, XMP /Metadata, /EmbeddedFiles, /PieceInfo,
                 rewrite + recompress content streams, regenerate trailer /ID
    image     -> Pillow: re-save without EXIF/XMP/ICC/text chunks
    docx/odt  -> zipfile: drop docProps/ and customXml/ parts
    unknown   -> returned as-is

Layer B (options.rewrite): after cleaning, send text to an OpenAI-compatible
chat completions endpoint to neutralize statistical token-sampling watermarks.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import os
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402

from text_unicode import clean_text, inspect_text  # noqa: E402  (repo module, stdlib only)

app = FastAPI(title="watermarks-remover", version="1.0.0-vercel")

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>watermarks-remover</title>
<style>
  :root {
    --bg: #0a0a0c; --surface: #131316; --surface-2: #1a1a1f;
    --border: rgba(255,255,255,.08); --border-strong: rgba(255,255,255,.16);
    --text: #f4f4f5; --muted: #a1a1aa; --dim: #71717a;
    --accent: #34d399; --accent-strong: #10b981; --accent-dim: rgba(52,211,153,.12);
    --danger: #f87171; --radius: 10px;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    min-height: 100dvh; display: flex; flex-direction: column; align-items: center;
    padding: 48px 20px 64px;
  }
  .wrap { width: 100%; max-width: 640px; }
  header { margin-bottom: 28px; }
  header h1 { font-size: 20px; font-weight: 650; letter-spacing: -.02em; }
  header p { color: var(--muted); font-size: 14px; margin-top: 4px; }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 24px;
  }
  .drop {
    border: 1.5px dashed var(--border-strong); border-radius: var(--radius);
    padding: 36px 20px; text-align: center; cursor: pointer; transition: border-color .15s, background .15s;
    background: var(--surface-2);
  }
  .drop:hover, .drop.over { border-color: var(--accent); }
  .drop .main { font-size: 15px; font-weight: 550; }
  .drop .sub { color: var(--dim); font-size: 13px; margin-top: 6px; }
  .drop.filled { border-style: solid; border-color: var(--accent-strong); padding: 22px 20px; }
  .drop.filled .fname { font-weight: 600; word-break: break-all; }
  .drop.filled .fmeta { color: var(--dim); font-size: 12.5px; margin-top: 4px; font-family: var(--mono); }
  .row { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-top: 20px; }
  label.toggle { display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 14px; color: var(--text); }
  label.toggle input { width: 16px; height: 16px; accent-color: var(--accent-strong); cursor: pointer; }
  .toggle-note { display: block; color: var(--dim); font-size: 12.5px; margin-top: 2px; }
  button.cta {
    background: var(--accent-strong); color: #052e1b; border: none; cursor: pointer;
    font: 600 14px/1 inherit; padding: 11px 22px; border-radius: var(--radius);
    transition: background .15s, transform .1s; white-space: nowrap; flex-shrink: 0;
  }
  button.cta:hover { background: var(--accent); }
  button.cta:active { transform: scale(.98); }
  button.cta:disabled { opacity: .5; cursor: default; }
  button.cta:disabled:active { transform: none; }
  .spinner {
    display: inline-block; width: 14px; height: 14px; vertical-align: -2px; margin-right: 8px;
    border: 2px solid rgba(5,46,27,.35); border-top-color: #052e1b; border-radius: 50%;
    animation: spin .7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  #error { display: none; margin-top: 16px; padding: 12px 14px; border-radius: var(--radius);
    background: rgba(248,113,113,.08); border: 1px solid rgba(248,113,113,.3); color: var(--danger);
    font-size: 13.5px; word-break: break-word; }
  .result { display: none; margin-top: 20px; }
  .result-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding-bottom: 14px; }
  .result-head .r-title { font-size: 15px; font-weight: 600; }
  .result-head .r-meta { color: var(--dim); font-size: 12.5px; font-family: var(--mono); margin-top: 2px; }
  a.download {
    background: var(--accent-dim); color: var(--accent); border: 1px solid rgba(52,211,153,.35);
    text-decoration: none; font: 600 13.5px/1 inherit; padding: 9px 16px; border-radius: var(--radius);
    white-space: nowrap; transition: background .15s;
  }
  a.download:hover { background: rgba(52,211,153,.2); }
  .notes { border-top: 1px solid var(--border); padding-top: 14px; }
  .notes h3 { font-size: 11.5px; text-transform: uppercase; letter-spacing: .09em; color: var(--dim); margin-bottom: 10px; font-weight: 600; }
  ul.notes-list { list-style: none; }
  ul.notes-list li {
    display: flex; gap: 10px; font-size: 13px; color: var(--muted);
    padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,.04); font-family: var(--mono);
  }
  ul.notes-list li:last-child { border-bottom: none; }
  ul.notes-list li::before { content: "//"; color: var(--accent); flex-shrink: 0; }
  ul.notes-list li.ok { color: var(--text); }
  footer { margin-top: 32px; color: var(--dim); font-size: 12.5px; }
  footer code { font-family: var(--mono); }
  footer a { color: var(--muted); text-decoration: none; }
  footer a:hover { color: var(--text); }
  input[type=file] { display: none; }
  @media (prefers-reduced-motion: reduce) { .spinner { animation: none; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>watermarks-remover</h1>
    <p>Strip AI provenance marks from your own files. PDF, text, images, DOCX in; clean versions out.</p>
  </header>
  <div class="card">
    <div class="drop" id="drop" role="button" tabindex="0" aria-label="Choose a file">
      <div class="main" id="dropMain">Drop a file here</div>
      <div class="sub" id="dropSub">or click to browse. PDF, text, images, DOCX.</div>
    </div>
    <div class="row">
      <label class="toggle">
        <input type="checkbox" id="rewrite">
        <span>Neural rewrite<span class="toggle-note">deepseek-v4-flash paraphrase for statistical text watermarks</span></span>
      </label>
      <button class="cta" id="go" disabled>Remove marks</button>
    </div>
    <div id="error"></div>
    <div class="result" id="result">
      <div class="result-head">
        <div>
          <div class="r-title">Cleaned</div>
          <div class="r-meta" id="rMeta"></div>
        </div>
        <a class="download" id="dl" download>Download PDF</a>
      </div>
      <div class="notes">
        <h3>Processing notes</h3>
        <ul class="notes-list" id="notes"></ul>
      </div>
    </div>
  </div>
  <footer>
    <code>/clean</code> JSON API: <code>POST {file: base64, name, options}</code> - <a href="/docs">OpenAPI</a>
  </footer>
</div>
<script>
(function () {
  var drop = document.getElementById("drop");
  var go = document.getElementById("go");
  var fileInput = document.createElement("input");
  fileInput.type = "file";
  fileInput.accept = ".pdf,.txt,.md,.html,.png,.jpg,.jpeg,.webp,.gif,.docx,.odt";
  fileInput.style.display = "none";
  document.body.appendChild(fileInput);
  var file = null;

  function pick(f) {
    if (!f) return;
    file = f;
    document.getElementById("dropMain").textContent = f.name;
    document.getElementById("dropSub").textContent = (f.size / 1024).toFixed(1) + " KB";
    drop.classList.add("filled");
    go.disabled = false;
    hideError();
  }
  drop.addEventListener("click", function () { fileInput.click(); });
  drop.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", function () { pick(fileInput.files[0]); });
  ["dragover", "dragenter"].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove("over"); });
  });
  drop.addEventListener("drop", function (e) { pick(e.dataTransfer.files[0]); });

  function showError(msg) {
    var el = document.getElementById("error");
    el.textContent = msg;
    el.style.display = "block";
  }
  function hideError() { document.getElementById("error").style.display = "none"; }

  go.addEventListener("click", function () {
    if (!file) return;
    var btn = go;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Removing';
    hideError();
    var reader = new FileReader();
    reader.onload = function () {
      var b64 = reader.result.split(",")[1];
      var rewrite = document.getElementById("rewrite").checked;
      fetch("/clean", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file: b64, name: file.name, options: { rewrite: rewrite } })
      }).then(function (r) {
        return r.json().then(function (j) { return { status: r.status, body: j }; });
      }).then(function (res) {
        if (!res.body.ok) { throw new Error(res.body.error || ("HTTP " + res.status)); }
        var j = res.body;
        var bin = atob(j.cleaned);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        var blob = new Blob([bytes], { type: "application/octet-stream" });
        var base = file.name.replace(/\.[^.]+$/, "");
        var ext = j.kind === "pdf" ? "pdf" : (file.name.split(".").pop() || "bin");
        var url = URL.createObjectURL(blob);
        var dl = document.getElementById("dl");
        dl.href = url;
        dl.download = base + ".cleaned." + ext;
        document.getElementById("rMeta").textContent =
          (file.size / 1024).toFixed(1) + " KB to " + (blob.size / 1024).toFixed(1) + " KB";
        renderNotes(j.report || {});
        document.getElementById("result").style.display = "block";
      }).catch(function (e) {
        showError("Failed: " + e.message);
      }).finally(function () {
        btn.disabled = false;
        btn.textContent = "Remove marks";
      });
    };
    reader.readAsDataURL(file);
  });

  function renderNotes(report) {
    var ul = document.getElementById("notes");
    ul.innerHTML = "";
    var lines = [];
    lines.push("handler: " + (report.handler || "none"));
    if (report.kind && report.kind !== "pdf") lines.push("kind: " + report.kind);
    (report.actions || []).forEach(function (a) { lines.push(a); });
    (report.removed || []).forEach(function (r) { lines.push("removed " + r); });
    (report.findings || []).forEach(function (f) { lines.push("found " + f); });
    var stats = report.stats || {};
    if (typeof stats.removed_count === "number") lines.push("hidden chars removed: " + stats.removed_count);
    if (stats.suspicious) lines.push("suspicious: " + stats.suspicious);
    if (report.layer_b) {
      lines.push("neural rewrite: " + (report.layer_b.rewritten ? "applied via " + (report.layer_b.model || "deepseek-v4-flash") : "skipped (" + (report.layer_b.note || "not requested") + ")"));
    }
    if (report.note) lines.push(report.note);
    if (!lines.length) lines.push("nothing suspicious found");
    lines.forEach(function (l) {
      var li = document.createElement("li");
      li.textContent = l;
      ul.appendChild(li);
    });
  }
})();
</script>
</body>
</html>
"""

MAX_INPUT_BYTES = 64 << 20  # 64 MiB decoded-file cap

TEXT_EXTS = {
    ".md", ".markdown", ".mdx", ".txt", ".text", ".html", ".htm", ".csv",
    ".json", ".yaml", ".yml", ".toml", ".xml", ".py", ".js", ".css", ".rs", ".go",
}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
ZIP_EXTS = {".docx", ".odt"}

REWRITE_SYSTEM_PROMPT = (
    "You are a professional editor. Rewrite the following text to remove "
    "statistical watermark patterns while preserving all facts, numbers, names, "
    "and structure. Output only the rewritten text."
)
REWRITE_MODEL = "deepseek-v4-flash"
REWRITE_URL = "https://opencode.ai/zen/go/v1/chat/completions"


# ---------------------------------------------------------------------------
# request decoding
# ---------------------------------------------------------------------------

def _decode_body(payload: dict[str, Any]) -> tuple[bytes, str]:
    file_b64 = payload.get("file")
    if not isinstance(file_b64, str) or not file_b64:
        raise ValueError("missing or invalid 'file' (base64 string required)")
    try:
        data = base64.b64decode(file_b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"'file' is not valid base64: {e}") from e
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"file too large: {len(data)} bytes > {MAX_INPUT_BYTES}")
    name = str(payload.get("name") or "input.bin")
    return data, Path(name.replace("\\", "/")).name


def _kind(data: bytes, name: str) -> str:
    ext = Path(name).suffix.lower()
    if ext in {".pdf"} or data[:4] == b"%PDF":
        return "pdf"
    if ext in ZIP_EXTS or data[:2] == b"PK":
        return "zip"
    if (
        ext in IMAGE_EXTS
        or data[:8] == b"\x89PNG\r\n\x1a\n"
        or data[:3] == b"\xff\xd8\xff"
        or data[:6] in (b"GIF87a", b"GIF89a")
        or (len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP")
    ):
        return "image"
    if ext in TEXT_EXTS:
        return "text"
    head = data[:8192]
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            pass
    return "unknown"


# ---------------------------------------------------------------------------
# Layer B rewrite (OpenAI-compatible chat completions)
# ---------------------------------------------------------------------------

def _layer_b_rewrite(text: str) -> tuple[str, dict[str, Any]]:
    api_key = os.environ.get("OPENCODE_GO_API_KEY", "").strip()
    if not api_key:
        return text, {"rewritten": False, "note": "OPENCODE_GO_API_KEY not set on server"}
    body = json.dumps(
        {
            "model": REWRITE_MODEL,
            "messages": [
                {"role": "system", "content": REWRITE_SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            "temperature": 0.7,
            "max_tokens": 2000,
        }
    ).encode("utf-8")
    # Cloudflare rejects the default Python-urllib UA with 1010; a browser-ish
    # UA is required. Never sent anywhere except the opencode-go gateway.
    req = urllib.request.Request(
        REWRITE_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "watermarks-remover/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        # LLM down must not fail the whole clean: return original text.
        return text, {"rewritten": False, "note": f"{type(e).__name__}: {e}"}
    content = payload["choices"][0]["message"]["content"].strip()
    return content, {"rewritten": True, "model": payload.get("model", REWRITE_MODEL)}


# ---------------------------------------------------------------------------
# cleaners
# ---------------------------------------------------------------------------

def _clean_pdf(data: bytes) -> tuple[bytes, dict[str, Any]]:
    import pikepdf

    actions: list[str] = []
    removed: list[str] = []
    src = pikepdf.open(io.BytesIO(data))

    info = src.trailer.get("/Info")
    if isinstance(info, pikepdf.Dictionary) and len(info) > 0:
        keys = [str(k) for k in info.keys()]
        removed.extend(f"Info/{k}" for k in keys)
        actions.append(f"removed /Info keys: {', '.join(keys)}")
        del src.trailer["/Info"]

    root = src.Root
    if root is not None:
        if "/Metadata" in root:
            removed.append("Root/Metadata")
            actions.append("removed XMP /Metadata stream")
            del root["/Metadata"]
        if "/PieceInfo" in root:
            removed.append("Root/PieceInfo")
            actions.append("removed doc-level /PieceInfo")
            del root["/PieceInfo"]
        names = root.get("/Names")
        if isinstance(names, pikepdf.Dictionary) and "/EmbeddedFiles" in names:
            removed.append("Names/EmbeddedFiles")
            actions.append("removed /EmbeddedFiles name tree")
            del names["/EmbeddedFiles"]

    n_streams = 0
    for page in src.pages:
        contents = page.get("/Contents")
        if contents is None:
            continue
        streams = contents if isinstance(contents, pikepdf.Array) else [contents]
        for s in streams:
            # Re-encode every content stream (done globally again at save via
            # compress_streams=True). Destroys byte-pattern steganography;
            # zero-width chars that are semantic text ride along and are
            # handled by the text layer (extract / Layer B rewrite).
            s.write(s.read_bytes())
            n_streams += 1
    actions.append(f"recompressed {n_streams} content stream(s)")

    src.trailer["/ID"] = pikepdf.Array(
        [pikepdf.String(os.urandom(16)), pikepdf.String(os.urandom(16))]
    )
    actions.append("regenerated trailer /ID")

    out = io.BytesIO()
    src.save(out, compress_streams=True)
    src.close()
    return out.getvalue(), {"actions": actions, "removed": removed}


def _clean_image(data: bytes) -> tuple[bytes, dict[str, Any]]:
    from PIL import Image

    actions: list[str] = []
    removed: list[str] = []
    img = Image.open(io.BytesIO(data))
    fmt = (img.format or "UNKNOWN").upper()

    meta_keys = list(img.info.keys()) if img.info else []
    try:
        exif = img.getexif()
        exif_keys = list(exif.keys()) if exif else []
    except Exception:
        exif_keys = []
    if meta_keys:
        removed.append(f"{fmt} metadata keys: {', '.join(str(k) for k in meta_keys[:20])}")
    if exif_keys:
        removed.append(f"{fmt} EXIF tags: {', '.join(str(k) for k in exif_keys[:20])}")

    out = io.BytesIO()
    if fmt == "JPEG":
        if img.mode not in ("RGB", "L", "CMYK"):
            img = img.convert("RGB")
        img.save(out, format="JPEG", quality=95)  # no exif=/icc_profile= -> dropped
        actions.append(
            f"JPEG re-saved without EXIF/XMP/ICC ({len(meta_keys)} info keys, {len(exif_keys)} exif tags dropped)"
        )
    elif fmt == "PNG":
        img.save(out, format="PNG")  # no pnginfo= -> tEXt/zTXt/iTXt/eXIf dropped
        actions.append(f"PNG re-saved without text/EXIF chunks ({len(meta_keys)} info keys dropped)")
    elif fmt == "WEBP":
        img.save(out, format="WEBP", quality=90)
        actions.append(f"WEBP re-saved without metadata ({len(meta_keys)} info keys dropped)")
    elif fmt == "GIF":
        img.save(out, format="GIF")
        actions.append(f"GIF re-saved without metadata ({len(meta_keys)} info keys dropped)")
    else:
        raise ValueError(f"unsupported image format: {fmt}")
    return out.getvalue(), {"actions": actions, "removed": removed}


def _clean_zip(data: bytes) -> tuple[bytes, dict[str, Any]]:
    actions: list[str] = []
    removed: list[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zin:
        names = zin.namelist()
        drop = [n for n in names if n.startswith("docProps/") or n.startswith("customXml/")]
        removed.extend(drop)
        keep = [n for n in names if n not in drop]
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
            for n in keep:
                zout.writestr(n, zin.read(n))
    if drop:
        actions.append(
            f"removed {len(drop)} metadata parts: "
            + ", ".join(drop[:10])
            + ("..." if len(drop) > 10 else "")
        )
    else:
        actions.append("no docProps/customXml parts found")
    return out.getvalue(), {"actions": actions, "removed": removed}


def _clean(data: bytes, name: str, options: dict[str, Any]) -> dict[str, Any]:
    kind = _kind(data, name)
    rewrite = bool((options or {}).get("rewrite"))

    if kind == "text":
        text = data.decode("utf-8", errors="surrogateescape")
        cleaned, stats = clean_text(text)
        report: dict[str, Any] = {"handler": "text_unicode.clean_text", "stats": stats}
        out = cleaned.encode("utf-8", errors="surrogateescape")
        if rewrite and len(cleaned) > 200:
            rewritten, lb = _layer_b_rewrite(cleaned)
            report["layer_b"] = lb
            if lb.get("rewritten"):
                out = rewritten.encode("utf-8")
        return {"kind": "text", "cleaned": out, "report": report}

    if kind == "pdf":
        out, report = _clean_pdf(data)
        return {"kind": "pdf", "cleaned": out, "report": {"handler": "pikepdf", **report}}

    if kind == "image":
        out, report = _clean_image(data)
        return {"kind": "image", "cleaned": out, "report": {"handler": "Pillow", **report}}

    if kind == "zip":
        out, report = _clean_zip(data)
        return {"kind": "container", "cleaned": out, "report": {"handler": "zipfile", **report}}

    return {
        "kind": "unknown",
        "cleaned": data,
        "report": {"handler": None, "note": "no handler for this format; returned as-is"},
    }


# ---------------------------------------------------------------------------
# inspectors
# ---------------------------------------------------------------------------

def _inspect(data: bytes, name: str) -> dict[str, Any]:
    kind = _kind(data, name)

    if kind == "text":
        text = data.decode("utf-8", errors="surrogateescape")
        rep = inspect_text(text).to_dict()
        return {"kind": "text", "suspicious": rep["suspicious_total"] > 0, "report": rep}

    if kind == "pdf":
        try:
            import pikepdf

            src = pikepdf.open(io.BytesIO(data))
            findings: list[str] = []
            info = src.trailer.get("/Info")
            if isinstance(info, pikepdf.Dictionary) and len(info):
                findings.append(f"/Info present: {', '.join(str(k) for k in info.keys())}")
            if "/Metadata" in src.Root:
                findings.append("/Metadata XMP stream present")
            names = src.Root.get("/Names")
            if isinstance(names, pikepdf.Dictionary) and "/EmbeddedFiles" in names:
                findings.append("/EmbeddedFiles present")
            src.close()
            return {"kind": "pdf", "suspicious": bool(findings), "report": {"findings": findings}}
        except Exception as e:
            return {"kind": "pdf", "suspicious": False, "report": {"note": f"pikepdf inspect failed: {e}"}}

    if kind == "image":
        try:
            from PIL import Image

            img = Image.open(io.BytesIO(data))
            fmt = img.format
            exif = img.getexif()
            exif_count = len(exif) if exif else 0
            info_keys = list(img.info.keys())
            suspicious = bool(info_keys) or exif_count > 0
            return {
                "kind": "image",
                "suspicious": suspicious,
                "report": {"format": fmt, "info_keys": info_keys[:20], "exif_tag_count": exif_count},
            }
        except Exception as e:
            return {"kind": "image", "suspicious": False, "report": {"note": str(e)}}

    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zin:
                names = zin.namelist()
            meta = [n for n in names if n.startswith("docProps/") or n.startswith("customXml/")]
            return {
                "kind": "container",
                "suspicious": bool(meta),
                "report": {"parts": len(names), "metadata_parts": meta},
            }
        except Exception as e:
            return {"kind": "container", "suspicious": False, "report": {"note": str(e)}}

    return {"kind": kind, "suspicious": False, "report": {"note": "no handler for this format"}}


# ---------------------------------------------------------------------------
# endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "version": "1.0.0-vercel"}


@app.get("/", include_in_schema=False)
def root():
    return HTMLResponse(INDEX_HTML)


@app.post("/inspect")
async def inspect(req: Request):
    try:
        payload = await req.json()
        data, name = _decode_body(payload)
    except Exception as e:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(e)})
    try:
        result = _inspect(data, name)
        return {"ok": True, **result}
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"ok": False, "error": f"inspect failed: {type(e).__name__}: {e}"}
        )


@app.post("/clean")
async def clean(req: Request):
    try:
        payload = await req.json()
        data, name = _decode_body(payload)
        options = payload.get("options") or {}
    except Exception as e:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(e)})
    try:
        result = _clean(data, name, options)
        return {
            "ok": True,
            "kind": result["kind"],
            "cleaned": base64.b64encode(result["cleaned"]).decode("ascii"),
            "report": result["report"],
        }
    except ValueError as e:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(e)})
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"ok": False, "error": f"clean failed: {type(e).__name__}: {e}"}
        )
