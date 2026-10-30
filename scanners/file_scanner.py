
import hashlib


def calculate_sha256(file_stream):
    """Calculate a file's SHA-256 hash without loading it all into memory."""
    sha256 = hashlib.sha256()

    while True:
        chunk = file_stream.read(4096)

        if not chunk:
            break

        sha256.update(chunk)

    return sha256.hexdigest()


def analyse_file(file_storage):
    """Calculate basic file metadata and its SHA-256 fingerprint."""

    if not file_storage or not file_storage.filename:
        raise ValueError("Please select a file.")

    original_name = file_storage.filename
    file_size = 0
    sha256 = hashlib.sha256()

    while True:
        chunk = file_storage.stream.read(4096)

        if not chunk:
            break

        file_size += len(chunk)

        if file_size > 10 * 1024 * 1024:
            raise ValueError("Files must be 10 MB or smaller.")

        sha256.update(chunk)

    if file_size == 0:
        raise ValueError("The selected file is empty.")

    return {
        "filename": original_name,
        "size": file_size,
        "sha256": sha256.hexdigest(),
        "verdict": "Fingerprint generated",
        "advice": (
            "The file fingerprint is ready for a threat-intelligence lookup. "
            "The fingerprint alone does not establish whether the file is safe."
        ),
    }
