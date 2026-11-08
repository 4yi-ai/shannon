"""Bounded binary ZIP staging. Tokens are single-use and bound to the SSO user."""
import json
import os
import re
import threading
import time
import uuid
import zipfile
from .security import validate_zip_directory
from pathlib import Path

MAX_ZIP_BYTES = 256 * 1024 * 1024
LEGACY_ZIP_BYTES = 32 * 1024 * 1024
ARCHIVE_QUOTA = 4 * 1024 ** 3
UPLOAD_TTL = 2 * 3600


class UploadError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class Uploads:
    def __init__(self, root):
        self.root = Path(root)
        self.directory = self.root / 'uploads'
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(2)
        self.reserved = {}

    def cleanup(self):
        for file in self.directory.iterdir():
            if file.stem not in self.reserved and file.is_file() and time.time() - file.stat().st_mtime > UPLOAD_TTL:
                file.unlink(missing_ok=True)

    def check_quota(self, additional=0):
        with self.lock:
            self.cleanup()
            used = sum(p.stat().st_size for p in (self.root / 'tasks').glob('*/source.zip'))
            used += sum(p.stat().st_size for p in self.directory.iterdir()
                        if p.suffix == '.zip' or p.suffix == '.part' and p.stem not in self.reserved)
            used += sum(self.reserved.values())
            if used + additional > ARCHIVE_QUOTA:
                raise UploadError('Source archive quota exceeded; contact operator', 507)

    def receive(self, stream, length, owner):
        if not 1 <= length <= MAX_ZIP_BYTES:
            raise UploadError('ZIP must be between 1 byte and 256 MiB', 413)
        if not self.slots.acquire(blocking=False):
            raise UploadError('Two ZIP uploads are already running; try again shortly', 429)
        token = uuid.uuid4().hex
        part, ready, metadata = [self.directory / (token + suffix) for suffix in ('.part', '.zip', '.json')]
        completed = False
        try:
            with self.lock:
                self.check_quota(length)
                self.reserved[token] = length
            deadline = time.monotonic() + 900
            with part.open('xb') as output:
                os.chmod(part, 0o600)
                remaining = length
                while remaining:
                    if time.monotonic() >= deadline:
                        raise UploadError('ZIP upload timed out', 408)
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise UploadError('ZIP upload was interrupted')
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            if not zipfile.is_zipfile(part):
                raise UploadError('The uploaded file is not a valid ZIP archive')
            try:
                validate_zip_directory(part)
            except ValueError as error:
                raise UploadError(str(error)) from None
            with self.lock:
                os.replace(part, ready)
                with metadata.open('x') as output:
                    os.chmod(metadata, 0o600)
                    json.dump({'owner': owner, 'created': time.time(), 'size': length}, output)
                    output.flush()
                    os.fsync(output.fileno())
                self.reserved.pop(token, None)
                completed = True
            return {'upload_id': token, 'size_bytes': length}
        finally:
            with self.lock:
                self.reserved.pop(token, None)
                if not completed:
                    for file in (part, ready, metadata):
                        file.unlink(missing_ok=True)
            self.slots.release()

    def resolve(self, token, owner):
        if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{32}', token):
            raise UploadError('Invalid uploaded ZIP reference')
        file = self.directory / (token + '.zip')
        try:
            metadata = json.loads(file.with_suffix('.json').read_text())
            if metadata['owner'] != owner or time.time() - metadata['created'] >= UPLOAD_TTL or not file.is_file():
                raise ValueError()
        except (OSError, ValueError, KeyError, TypeError):
            raise UploadError('Uploaded ZIP is missing, expired, already used, or belongs to another user') from None
        return file

    def consume(self, token, owner, destination):
        with self.lock:
            file = self.resolve(token, owner)
            os.replace(file, destination)
            file.with_suffix('.json').unlink(missing_ok=True)
