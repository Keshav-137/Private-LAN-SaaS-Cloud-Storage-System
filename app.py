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

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Private SaaS Cloud - HDFS Controller</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body class="bg-light">
<main class="container py-5">
    <section class="p-4 bg-white rounded shadow-sm mb-4">
        <h1 class="h2">Private SaaS Cloud Controller</h1>
        <p class="text-muted mb-0">SDG 9: Secure LAN Storage with HDFS and encryption</p>
    </section>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }}" role="alert">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    <section class="card p-4 mb-4 shadow-sm">
        <h2 class="h4">Upload and encrypt a file</h2>
        <form action="{{ url_for('upload_file') }}" method="post" enctype="multipart/form-data">
            <div class="mb-3">
                <input class="form-control" type="file" name="file" required>
            </div>
            <button type="submit" class="btn btn-primary">Encrypt and store to HDFS</button>
        </form>
    </section>
    <section class="card p-4 shadow-sm">
        <h2 class="h4">Stored files in HDFS SaaS Vault</h2>
        <table class="table table-bordered mt-3">
            <thead class="table-dark">
                <tr><th>Filename</th><th>Action</th></tr>
            </thead>
            <tbody>
                {% for file_id, filename in files %}
                <tr>
                    <td>{{ filename }}</td>
                    <td><a href="{{ url_for('download_file', file_id=file_id) }}"
                           class="btn btn-sm btn-success">Decrypt and download</a></td>
                </tr>
                {% else %}
                <tr><td colspan="2" class="text-center">No files uploaded yet.</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </section>
</main>
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
