"""Admission controls. Runtime network isolation must also be enforced externally."""
import ipaddress
import socket
import struct
from contextlib import nullcontext
import stat
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


def public_url(value, allowed_origins=None, resolver=socket.getaddrinfo):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
        raise ValueError('Invalid URL')
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Only HTTPS URLs without credentials or fragments are accepted')
    host = parsed.hostname.encode('idna').decode('ascii').lower().rstrip('.')
    if host == 'localhost' or host.endswith(('.localhost', '.local', '.internal', '.svc', '.cluster.local')):
        raise ValueError('Internal hosts are forbidden')
    port = parsed.port or 443
    if port != 443:
        raise ValueError('Only port 443 is allowed for the internal trial')
    origin = 'https://' + ('[' + host + ']' if ':' in host else host)
    if allowed_origins is not None and origin not in allowed_origins:
        raise ValueError('Target origin is not in the operator authorization allowlist')
    addresses = {item[4][0] for item in resolver(host, port, type=socket.SOCK_STREAM)}
    if not addresses:
        raise ValueError('Host has no addresses')
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global or (ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo)):
            raise ValueError('Private, metadata, reserved and transition addresses are forbidden')
    return origin + (parsed.path or '/') + (('?' + parsed.query) if parsed.query else '')


def validate_zip_directory(archive, max_files=50000):
    # Bound metadata before ZipFile materializes the entire central directory.
    context = nullcontext(archive) if hasattr(archive, 'read') else open(archive, 'rb')
    with context as stream:
        original = stream.tell()
        try:
            stream.seek(0, 2);size = stream.tell()
            start = max(0, size - 65557)
            stream.seek(start);tail = stream.read(65557)
            index = tail.rfind(b'PK\x05\x06')
            if index < 0 or len(tail) - index < 22:
                raise ValueError('Invalid ZIP directory')
            _, disk, directory_disk, disk_count, count, directory_bytes, offset, comment = struct.unpack_from('<4s4H2LH', tail, index)
            if disk or directory_disk or disk_count != count or count > max_files or count == 65535:
                raise ValueError('ZIP has too many files or uses unsupported split/ZIP64 format')
            if tail[max(0,index-20):index-16] == b'PK\x06\x07' or directory_bytes == 0xffffffff or offset == 0xffffffff:
                raise ValueError('ZIP64 source archives are not supported')
            if directory_bytes > 32 * 1024 * 1024 or offset + directory_bytes > start + index or index + 22 + comment != len(tail):
                raise ValueError('ZIP directory exceeds safe source limits')
        finally:
            stream.seek(original)


def extract_zip(archive, destination, max_bytes=1024 * 1024 * 1024, max_files=50000):
    destination = Path(destination)
    validate_zip_directory(archive, max_files)
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if not entries or len(entries) > max_files:
            raise ValueError('ZIP must contain between 1 and 50000 entries')
        total = 0
        names = set()
        for item in entries:
            name = item.filename
            parts = PurePosixPath(name).parts
            mode = item.external_attr >> 16
            if (not parts or name.startswith('/') or '\\' in name or '\x00' in name
                    or any(p.casefold() in ('..', '.git', '.shannon') or ':' in p for p in parts)
                    or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise ValueError('ZIP contains an unsafe path or file type')
            if name in names:
                raise ValueError('ZIP contains duplicate paths')
            names.add(name)
            total += item.file_size
            if total > max_bytes or (item.file_size > 1048576 and item.file_size > max(item.compress_size, 1) * 200):
                raise ValueError('ZIP exceeds extraction limits')
        destination.mkdir(parents=True, exist_ok=True)
        written = 0
        for item in entries:
            target = destination.joinpath(*PurePosixPath(item.filename).parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(item) as src, target.open('xb') as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError('ZIP exceeds extraction limits')
                    dst.write(chunk)
    files = list(destination.iterdir())
    return files[0] if len(files) == 1 and files[0].is_dir() else destination
