import json
import logging
import os
import threading
import uuid
from io import BytesIO
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, flash, redirect, render_template_string, request, send_file, url_for
from hdfs import InsecureClient
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or ""
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_BYTES", 100 * 1024 * 1024))
app.config["HDFS_URL"] = os.environ.get("HDFS_URL", "http://localhost:9870")
app.config["HDFS_USER"] = os.environ.get("HDFS_USER", "hadoop")
app.config["HDFS_BASE_DIR"] = os.environ.get("HDFS_BASE_DIR", "/saas_cloud")
app.config["BLOCK_SIZE"] = 2 * 1024 * 1024

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("SAAS_DATA_DIR", Path(__file__).resolve().parent))
KEY_FILE = DATA_DIR / "secret.key"
METADATA_FILE = DATA_DIR / "files.json"
METADATA_LOCK = threading.RLock()


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as key_file:
            key = Fernet.generate_key()
            key_file.write(key)
            return key
    except FileExistsError:
        return path.read_bytes()


if not app.secret_key:
    app.secret_key = load_or_create_key(DATA_DIR / "flask-secret.key").decode("ascii")

cipher = Fernet(load_or_create_key(KEY_FILE))
client = InsecureClient(app.config["HDFS_URL"], user=app.config["HDFS_USER"])

# Drop-in replacement for HTML_TEMPLATE in app.py.
# No backend changes needed: it uses the same routes (index, upload_file, download_file)
# and the same variables (files, flashed messages).

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Private SaaS Cloud - HDFS Controller</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        :root {
            --ink: #1b2a2f;
            --paper: #eef2f1;
            --panel: #ffffff;
            --line: #d3dcda;
            --teal: #0f6b66;
            --teal-dark: #0a4f4b;
            --brass: #b7832f;
            --muted: #5b6b6e;
        }
        body { background: var(--paper); color: var(--ink); font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
        .vault-head { background: var(--ink); color: #f3f6f5; border-radius: 14px; padding: 1.75rem 2rem; }
        .vault-head h1 { font-size: 1.6rem; font-weight: 650; margin: 0; }
        .vault-head p { color: #a9bbbc; margin: .35rem 0 0; }
        .vault-stats { display: flex; gap: 1.5rem; margin-top: 1.1rem; font-size: .9rem; color: #c9d6d6; }
        .vault-stats strong { color: #fff; font-size: 1.15rem; margin-right: .3rem; }
        .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 1.5rem; }

        #drop-zone {
            display: block; cursor: pointer; text-align: center;
            border: 2px dashed #9db3b0; border-radius: 10px;
            padding: 2.2rem 1rem; background: #f7faf9;
            transition: border-color .15s, background .15s;
        }
        #drop-zone:hover, #drop-zone:focus-within { border-color: var(--teal); }
        #drop-zone.dragging { border-color: var(--teal); background: #e3f1ef; }
        #drop-zone.has-file { border-style: solid; border-color: var(--teal); background: #eaf5f3; }
        #drop-zone input { position: absolute; width: 1px; height: 1px; opacity: 0; }
        #drop-title { font-weight: 600; }
        #drop-hint { color: var(--muted); font-size: .9rem; }

        .btn-vault { background: var(--teal); border-color: var(--teal); color: #fff; }
        .btn-vault:hover, .btn-vault:focus { background: var(--teal-dark); border-color: var(--teal-dark); color: #fff; }
        .btn-vault:disabled { background: #7fa9a6; border-color: #7fa9a6; color: #fff; }

        #progress-wrap { display: none; margin-top: 1rem; }
        .progress { height: 10px; background: #dbe5e3; }
        .progress-bar { background: var(--teal); transition: width .1s linear; }
        #progress-label { font-size: .9rem; color: var(--muted); margin-top: .4rem; }

        .file-row td { vertical-align: middle; }
        .file-badge {
            display: inline-flex; align-items: center; justify-content: center;
            width: 2.6rem; height: 2rem; border-radius: 6px; margin-right: .75rem;
            background: #e4ecea; color: var(--teal-dark); font-size: .7rem; font-weight: 700;
        }
        .file-row.just-added { animation: flash-in 1.6s ease-out; }
        @keyframes flash-in { from { background: #f6e7c6; } to { background: transparent; } }
        .lock { color: var(--brass); }
        .sort-btn { cursor: pointer; user-select: none; }
        .sort-btn:hover { text-decoration: underline; }

        .spinner-border-sm { margin-right: .4rem; }
        .toolbar { display: flex; gap: .75rem; flex-wrap: wrap; align-items: center; justify-content: space-between; }
        .toolbar input { max-width: 18rem; }

        @media (prefers-reduced-motion: reduce) {
            .file-row.just-added { animation: none; }
            .progress-bar { transition: none; }
        }
    </style>
</head>
<body>
<main class="container py-4 py-md-5" style="max-width: 860px;">

    <header class="vault-head mb-4">
        <h1>Private SaaS Cloud Controller</h1>
        <p>SDG 9: Secure LAN storage with HDFS and encryption</p>
        <div class="vault-stats">
            <span><strong id="stat-count">{{ files|length }}</strong>files in the vault</span>
            <span><strong>AES</strong>encrypted before storage</span>
        </div>
    </header>

    <div id="flash" aria-live="polite">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                {{ message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
          {% endfor %}
        {% endwith %}
    </div>

    <section class="panel mb-4">
        <h2 class="h5 mb-3">Upload and encrypt a file</h2>
        <form id="upload-form" action="{{ url_for('upload_file') }}" method="post" enctype="multipart/form-data">
            <label id="drop-zone" for="file-input">
                <input id="file-input" type="file" name="file" required>
                <div id="drop-title">Drop a file here, or click to choose one</div>
                <div id="drop-hint">The file is encrypted on the server, then split into blocks in HDFS.</div>
            </label>

            <div id="progress-wrap">
                <div class="progress" role="progressbar" aria-label="Upload progress">
                    <div id="progress-bar" class="progress-bar" style="width: 0%"></div>
                </div>
                <div id="progress-label"></div>
            </div>

            <div class="d-flex gap-2 mt-3">
                <button id="upload-btn" type="submit" class="btn btn-vault" disabled>Encrypt and store to HDFS</button>
                <button id="clear-btn" type="button" class="btn btn-outline-secondary" hidden>Clear selection</button>
            </div>
        </form>
    </section>

    <section id="files" class="panel">
        <div class="toolbar mb-3">
            <h2 class="h5 mb-0">Stored files in HDFS SaaS Vault</h2>
            <input id="search" type="search" class="form-control form-control-sm" placeholder="Search files" aria-label="Search files">
        </div>

        <table class="table align-middle mb-0">
            <thead>
                <tr>
                    <th><span id="sort-name" class="sort-btn" role="button" tabindex="0">Filename <span id="sort-arrow">&#9650;</span></span></th>
                    <th class="text-end">Action</th>
                </tr>
            </thead>
            <tbody id="files-body">
                {% for file_id, filename in files %}
                <tr class="file-row" data-name="{{ filename|lower }}">
                    <td>
                        <span class="file-badge" data-ext-for="{{ filename }}"></span>
                        <span class="file-name">{{ filename }}</span>
                    </td>
                    <td class="text-end">
                        <a href="{{ url_for('download_file', file_id=file_id) }}"
                           class="btn btn-sm btn-vault" data-download>Decrypt and download</a>
                    </td>
                </tr>
                {% else %}
                <tr class="empty-row">
                    <td colspan="2" class="text-center text-muted py-4">The vault is empty. Upload a file to get started.</td>
                </tr>
                {% endfor %}
                <tr id="no-match" hidden>
                    <td colspan="2" class="text-center text-muted py-4">No files match your search.</td>
                </tr>
            </tbody>
        </table>
    </section>
</main>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
(function () {
    var form = document.getElementById('upload-form');
    var input = document.getElementById('file-input');
    var zone = document.getElementById('drop-zone');
    var title = document.getElementById('drop-title');
    var hint = document.getElementById('drop-hint');
    var uploadBtn = document.getElementById('upload-btn');
    var clearBtn = document.getElementById('clear-btn');
    var progressWrap = document.getElementById('progress-wrap');
    var progressBar = document.getElementById('progress-bar');
    var progressLabel = document.getElementById('progress-label');
    var flash = document.getElementById('flash');
    var searchBox = document.getElementById('search');
    var sortAsc = true;

    var DEFAULT_TITLE = title.textContent;
    var DEFAULT_HINT = hint.textContent;

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    }

    function showFlash(category, message) {
        var div = document.createElement('div');
        div.className = 'alert alert-' + category + ' alert-dismissible fade show';
        div.setAttribute('role', 'alert');
        div.textContent = message;
        var close = document.createElement('button');
        close.type = 'button';
        close.className = 'btn-close';
        close.setAttribute('data-bs-dismiss', 'alert');
        close.setAttribute('aria-label', 'Close');
        div.appendChild(close);
        flash.appendChild(div);
        autoDismiss();
    }

    function autoDismiss() {
        flash.querySelectorAll('.alert-success, .alert-info').forEach(function (el) {
            if (el.dataset.timer) return;
            el.dataset.timer = '1';
            setTimeout(function () {
                if (window.bootstrap && el.isConnected) {
                    bootstrap.Alert.getOrCreateInstance(el).close();
                }
            }, 6000);
        });
    }

    function setSelected(file) {
        if (file) {
            title.textContent = file.name;
            hint.textContent = formatSize(file.size) + ' ready to encrypt';
            zone.classList.add('has-file');
            uploadBtn.disabled = false;
            clearBtn.hidden = false;
        } else {
            title.textContent = DEFAULT_TITLE;
            hint.textContent = DEFAULT_HINT;
            zone.classList.remove('has-file');
            uploadBtn.disabled = true;
            clearBtn.hidden = true;
        }
    }

    input.addEventListener('change', function () { setSelected(input.files[0]); });
    clearBtn.addEventListener('click', function () { input.value = ''; setSelected(null); });

    ['dragenter', 'dragover'].forEach(function (evt) {
        zone.addEventListener(evt, function (e) { e.preventDefault(); zone.classList.add('dragging'); });
    });
    ['dragleave', 'drop'].forEach(function (evt) {
        zone.addEventListener(evt, function (e) { e.preventDefault(); zone.classList.remove('dragging'); });
    });
    zone.addEventListener('drop', function (e) {
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            setSelected(input.files[0]);
        }
    });

    // Upload with a progress bar, then refresh the file list without a full page reload.
    form.addEventListener('submit', function (e) {
        if (!window.XMLHttpRequest || !window.FormData || !window.DOMParser) return;
        if (!input.files.length) return;
        e.preventDefault();

        var knownNames = Array.prototype.map.call(document.querySelectorAll('.file-row'), function (r) {
            return r.querySelector('.file-name').textContent;
        });

        var xhr = new XMLHttpRequest();
        xhr.open('POST', form.action);
        progressWrap.style.display = 'block';
        progressBar.style.width = '0%';
        progressBar.classList.remove('progress-bar-striped', 'progress-bar-animated');
        progressLabel.textContent = 'Uploading...';
        uploadBtn.disabled = true;
        uploadBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>Working...';

        xhr.upload.onprogress = function (ev) {
            if (!ev.lengthComputable) return;
            var pct = Math.round((ev.loaded / ev.total) * 100);
            progressBar.style.width = pct + '%';
            progressLabel.textContent = 'Uploading... ' + pct + '%';
        };
        xhr.upload.onload = function () {
            progressBar.style.width = '100%';
            progressBar.classList.add('progress-bar-striped', 'progress-bar-animated');
            progressLabel.textContent = 'Encrypting and writing blocks to HDFS...';
        };
        xhr.onerror = function () {
            resetUploadUi();
            showFlash('danger', 'Could not reach the server. Check your connection and try again.');
        };
        xhr.onload = function () {
            // The server redirects back to the index page; read the refreshed page from the response.
            var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
            var newFlash = doc.getElementById('flash');
            var newFiles = doc.getElementById('files');
            if (!newFiles) {
                resetUploadUi();
                showFlash('danger', 'Upload finished but the page could not be refreshed. Reload to see your files.');
                return;
            }
            flash.innerHTML = newFlash ? newFlash.innerHTML : '';
            document.getElementById('files').innerHTML = newFiles.innerHTML;
            document.getElementById('stat-count').textContent = document.querySelectorAll('.file-row').length;
            document.querySelectorAll('.file-row').forEach(function (row) {
                if (knownNames.indexOf(row.querySelector('.file-name').textContent) === -1) {
                    row.classList.add('just-added');
                }
            });
            input.value = '';
            setSelected(null);
            resetUploadUi();
            bindFilesUi();
            autoDismiss();
        };
        xhr.send(new FormData(form));
    });

    function resetUploadUi() {
        progressWrap.style.display = 'none';
        uploadBtn.textContent = 'Encrypt and store to HDFS';
        uploadBtn.disabled = !input.files.length;
    }

    // Download button: show a decrypting state (the browser handles the actual download).
    document.addEventListener('click', function (e) {
        var link = e.target.closest ? e.target.closest('a[data-download]') : null;
        if (!link || link.dataset.busy) return;
        link.dataset.busy = '1';
        var original = link.textContent;
        link.classList.add('disabled');
        link.innerHTML = '<span class="spinner-border spinner-border-sm"></span>Decrypting...';
        setTimeout(function () {
            link.textContent = original;
            link.classList.remove('disabled');
            delete link.dataset.busy;
        }, 4000);
    });

    // Search and sort
    function applyFilter() {
        var q = searchBox.value.trim().toLowerCase();
        var rows = document.querySelectorAll('.file-row');
        var visible = 0;
        rows.forEach(function (row) {
            var show = row.dataset.name.indexOf(q) !== -1;
            row.hidden = !show;
            if (show) visible++;
        });
        var noMatch = document.getElementById('no-match');
        if (noMatch) noMatch.hidden = !(rows.length > 0 && visible === 0);
    }

    function applySort() {
        var body = document.getElementById('files-body');
        var rows = Array.prototype.slice.call(body.querySelectorAll('.file-row'));
        rows.sort(function (a, b) {
            return sortAsc ? a.dataset.name.localeCompare(b.dataset.name) : b.dataset.name.localeCompare(a.dataset.name);
        });
        var anchor = document.getElementById('no-match');
        rows.forEach(function (r) { body.insertBefore(r, anchor); });
        document.getElementById('sort-arrow').innerHTML = sortAsc ? '&#9650;' : '&#9660;';
    }

    function paintBadges() {
        document.querySelectorAll('[data-ext-for]').forEach(function (el) {
            var name = el.getAttribute('data-ext-for');
            var dot = name.lastIndexOf('.');
            el.textContent = dot > -1 ? name.slice(dot + 1, dot + 5).toUpperCase() : 'FILE';
        });
    }

    function bindFilesUi() {
        paintBadges();
        var sortBtn = document.getElementById('sort-name');
        var box = document.getElementById('search');
        searchBox = box;
        box.addEventListener('input', applyFilter);
        function toggle() { sortAsc = !sortAsc; applySort(); }
        sortBtn.addEventListener('click', toggle);
        sortBtn.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
        });
        applySort();
        applyFilter();
    }

    bindFilesUi();
    autoDismiss();
})();
</script>
</body>
</html>
"""


def read_metadata() -> dict[str, dict[str, Any]]:
    with METADATA_LOCK:
        if not METADATA_FILE.exists():
            return {}
        try:
            data = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            logger.exception("Could not read file metadata")
            raise RuntimeError("File metadata is unavailable.") from error
        if not isinstance(data, dict):
            raise RuntimeError("File metadata has an invalid format.")
        return data


def write_metadata(metadata: dict[str, dict[str, Any]]) -> None:
    with METADATA_LOCK:
        temporary_file = METADATA_FILE.with_suffix(".tmp")
        try:
            temporary_file.write_text(json.dumps(metadata), encoding="utf-8")
            temporary_file.replace(METADATA_FILE)
        except OSError:
            logger.exception("Could not persist file metadata")
            raise


@app.errorhandler(413)
def upload_too_large(error: Exception) -> tuple[str, int]:
    logger.warning("Rejected upload exceeding the configured size limit: %s", error)
    return "File exceeds the configured upload size limit.", 413


@app.route("/")
def index() -> str:
    try:
        metadata = read_metadata()
    except RuntimeError as error:
        flash(str(error), "danger")
        metadata = {}
    files = sorted(
        ((file_id, str(item.get("filename", "Unnamed file"))) for file_id, item in metadata.items()),
        key=lambda item: item[1].casefold(),
    )
    return render_template_string(HTML_TEMPLATE, files=files)


@app.route("/upload", methods=["POST"])
def upload_file():
    uploaded_file = request.files.get("file")
    if uploaded_file is None or not uploaded_file.filename:
        flash("Choose a file to upload.", "warning")
        return redirect(url_for("index"))

    filename = secure_filename(uploaded_file.filename)
    if not filename:
        flash("The uploaded filename is not valid.", "warning")
        return redirect(url_for("index"))

    file_id = uuid.uuid4().hex
    hdfs_dir = app.config["HDFS_BASE_DIR"]
    block_size = app.config["BLOCK_SIZE"]
    try:
        encrypted_bytes = cipher.encrypt(uploaded_file.read())
        chunks = [
            encrypted_bytes[offset : offset + block_size]
            for offset in range(0, len(encrypted_bytes), block_size)
        ]

        client.makedirs(hdfs_dir)
        for index, chunk in enumerate(chunks):
            chunk_path = f"{hdfs_dir}/{file_id}.part_{index}"
            with client.write(chunk_path, overwrite=False) as writer:
                writer.write(chunk)

        with METADATA_LOCK:
            metadata = read_metadata()
            metadata[file_id] = {"filename": filename, "chunks": len(chunks)}
            write_metadata(metadata)
    except Exception:
        logger.exception("File upload failed for %s", filename)
        flash("Upload failed while encrypting or storing the file. Check the server log.", "danger")
        return redirect(url_for("index"))

    flash(f"{filename} was encrypted and stored successfully.", "success")
    return redirect(url_for("index"))


@app.route("/download/<file_id>")
def download_file(file_id: str):
    if len(file_id) != 32 or any(character not in "0123456789abcdef" for character in file_id):
        return "File not found.", 404

    try:
        metadata = read_metadata()
        file_info = metadata.get(file_id)
        if file_info is None:
            return "File not found.", 404

        chunk_count = int(file_info["chunks"])
        if chunk_count < 1:
            raise ValueError("File metadata contains no chunks.")

        encrypted_bytes = bytearray()
        for index in range(chunk_count):
            chunk_path = f"{app.config['HDFS_BASE_DIR']}/{file_id}.part_{index}"
            with client.read(chunk_path) as reader:
                encrypted_bytes.extend(reader.read())

        decrypted_bytes = cipher.decrypt(bytes(encrypted_bytes))
    except InvalidToken:
        logger.exception("Stored file failed its encryption integrity check: %s", file_id)
        flash("The stored file could not be decrypted.", "danger")
        return redirect(url_for("index"))
    except Exception:
        logger.exception("File download failed: %s", file_id)
        flash("Download failed while reading or decrypting the file. Check the server log.", "danger")
        return redirect(url_for("index"))

    return send_file(
        BytesIO(decrypted_bytes),
        as_attachment=True,
        download_name=str(file_info.get("filename", "download")),
    )


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").lower() == "true",
    )
