"""
Archive source provider for scanning compressed archives.

This module implements archive type detection, extraction, and recursive scanning
with configurable depth limits. It supports multiple archive formats including
zip, tar, gzip, bzip2, xz, 7z, rar, and zstandard.
"""

import asyncio
import bz2
import gzip
import io
import lzma
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Callable, BinaryIO

try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False

try:
    import rarfile
    HAS_RAR = True
except ImportError:
    HAS_RAR = False

try:
    import zstandard
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

from ..config.models import Config
from ..logging import get_logger
from .common import normalize_path, should_skip_path
from .fragment import Fragment


# Type alias for the callback function used to yield fragments
FragmentsFunc = Callable[[Fragment, Optional[Exception]], Optional[Exception]]


# Archive magic bytes for detection
ARCHIVE_MAGIC_BYTES = {
    b'PK\x03\x04': 'zip',
    b'PK\x05\x06': 'zip',
    b'PK\x07\x08': 'zip',
    b'\x1f\x8b': 'gzip',
    b'BZ': 'bzip2',
    b'\xfd7zXZ\x00': 'xz',
    b'7z\xbc\xaf\x27\x1c': '7z',
    b'Rar!\x1a\x07': 'rar',
    b'Rar!\x1a\x07\x01\x00': 'rar',
    b'\x28\xb5\x2f\xfd': 'zstd',
}


# Tar magic bytes are at offset 257
TAR_MAGIC = [b'ustar\x00', b'ustar  \x00']


def detect_archive_type_from_bytes(data: bytes) -> Optional[str]:
    """
    Detect archive type from file content using magic bytes.

    Args:
        data: First bytes of the file (at least 512 bytes for tar detection)

    Returns:
        Archive type string or None if not recognized
    """
    if len(data) < 8:
        return None

    # Check common magic bytes
    for magic, archive_type in ARCHIVE_MAGIC_BYTES.items():
        if data.startswith(magic):
            return archive_type

    # Check for tar (magic at offset 257)
    if len(data) >= 262:
        for tar_magic in TAR_MAGIC:
            if data[257:257+len(tar_magic)] == tar_magic:
                return 'tar'

    return None


def detect_archive_type(path: str) -> Optional[str]:
    """
    Detect archive type from file extension and magic bytes.

    Args:
        path: File path to check

    Returns:
        Archive type string or None if not an archive
    """
    path_lower = path.lower()

    # Extension-based detection
    if path_lower.endswith('.zip'):
        return 'zip'
    elif path_lower.endswith(('.tar.gz', '.tgz')):
        return 'tar.gz'
    elif path_lower.endswith(('.tar.bz2', '.tbz2')):
        return 'tar.bz2'
    elif path_lower.endswith(('.tar.xz', '.txz')):
        return 'tar.xz'
    elif path_lower.endswith('.tar.zst'):
        return 'tar.zst'
    elif path_lower.endswith('.tar'):
        return 'tar'
    elif path_lower.endswith('.gz'):
        return 'gzip'
    elif path_lower.endswith('.bz2'):
        return 'bzip2'
    elif path_lower.endswith('.xz'):
        return 'xz'
    elif path_lower.endswith('.7z'):
        return '7z'
    elif path_lower.endswith('.rar'):
        return 'rar'
    elif path_lower.endswith('.zst'):
        return 'zstd'

    return None


async def scan_zip_archive(
    reader: BinaryIO,
    path: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """
    Scan a ZIP archive, extracting and processing each file.

    Args:
        reader: Binary reader for the archive
        path: Path to the archive
        config: Gitleaks configuration
        outer_paths: List of container archive paths
        max_archive_depth: Maximum nesting depth allowed
        archive_depth: Current nesting depth
        yield_func: Callback to process fragments
    """
    logger = get_logger()

    try:
        # ZIP requires seekable file, so we may need to use a temp file
        # or read into memory
        if hasattr(reader, 'seek'):
            zip_file = zipfile.ZipFile(reader, 'r')
        else:
            # Read into memory
            data = reader.read()
            zip_file = zipfile.ZipFile(io.BytesIO(data), 'r')

        with zip_file:
            for info in zip_file.infolist():
                # Skip directories
                if info.is_dir():
                    continue

                # Build virtual path
                inner_path = normalize_path(info.filename)
                new_outer_paths = outer_paths + [normalize_path(path)]
                virtual_path = "!".join(new_outer_paths + [inner_path])

                # Check allowlist
                if should_skip_path(config, virtual_path):
                    logger.debug("skipping archive entry: global allowlist", path=virtual_path)
                    continue

                try:
                    # Extract file
                    with zip_file.open(info) as entry_file:
                        # Import File here to avoid circular import
                        from .file import File

                        # Check if this entry is itself an archive
                        archive_type = detect_archive_type(inner_path)

                        if archive_type and archive_depth + 1 <= max_archive_depth:
                            # Recursively scan nested archive
                            logger.debug(
                                "scanning nested archive",
                                path=virtual_path,
                                depth=archive_depth + 1
                            )

                            await scan_archive(
                                entry_file,
                                inner_path,
                                archive_type,
                                config,
                                new_outer_paths,
                                max_archive_depth,
                                archive_depth + 1,
                                yield_func
                            )
                        else:
                            # Scan as regular file
                            file_source = File(
                                content=entry_file,
                                path=inner_path,
                                config=config,
                                outer_paths=new_outer_paths,
                                max_archive_depth=max_archive_depth,
                                archive_depth=archive_depth + 1,
                            )

                            await file_source.fragments(yield_func)

                except Exception as e:
                    logger.warning("error extracting archive entry", path=virtual_path, error=str(e))
                    continue

    except Exception as e:
        logger.error("error reading zip archive", path=path, error=str(e))


async def scan_tar_archive(
    reader: BinaryIO,
    path: str,
    archive_type: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """
    Scan a TAR archive (possibly compressed), extracting and processing each file.

    Args:
        reader: Binary reader for the archive
        path: Path to the archive
        archive_type: Type of archive (tar, tar.gz, tar.bz2, tar.xz, tar.zst)
        config: Gitleaks configuration
        outer_paths: List of container archive paths
        max_archive_depth: Maximum nesting depth allowed
        archive_depth: Current nesting depth
        yield_func: Callback to process fragments
    """
    logger = get_logger()

    try:
        # Determine compression mode
        if archive_type == 'tar.gz':
            mode = 'r:gz'
        elif archive_type == 'tar.bz2':
            mode = 'r:bz2'
        elif archive_type == 'tar.xz':
            mode = 'r:xz'
        elif archive_type == 'tar.zst':
            # Decompress zstd first, then open tar
            if not HAS_ZSTD:
                logger.warning("zstandard library not available, skipping tar.zst", path=path)
                return

            dctx = zstandard.ZstdDecompressor()
            decompressed_data = dctx.stream_reader(reader)
            tar_file = tarfile.open(fileobj=decompressed_data, mode='r|')
        else:
            mode = 'r'
            tar_file = tarfile.open(fileobj=reader, mode=mode)

        # Open tar file if not already opened
        if archive_type != 'tar.zst':
            tar_file = tarfile.open(fileobj=reader, mode=mode)

        with tar_file:
            for member in tar_file:
                # Skip directories and special files
                if not member.isfile():
                    continue

                # Build virtual path
                inner_path = normalize_path(member.name)
                new_outer_paths = outer_paths + [normalize_path(path)]
                virtual_path = "!".join(new_outer_paths + [inner_path])

                # Check allowlist
                if should_skip_path(config, virtual_path):
                    logger.debug("skipping archive entry: global allowlist", path=virtual_path)
                    continue

                try:
                    # Extract file
                    entry_file = tar_file.extractfile(member)
                    if entry_file is None:
                        continue

                    with entry_file:
                        # Import File here to avoid circular import
                        from .file import File

                        # Check if this entry is itself an archive
                        entry_archive_type = detect_archive_type(inner_path)

                        if entry_archive_type and archive_depth + 1 <= max_archive_depth:
                            # Recursively scan nested archive
                            logger.debug(
                                "scanning nested archive",
                                path=virtual_path,
                                depth=archive_depth + 1
                            )

                            await scan_archive(
                                entry_file,
                                inner_path,
                                entry_archive_type,
                                config,
                                new_outer_paths,
                                max_archive_depth,
                                archive_depth + 1,
                                yield_func
                            )
                        else:
                            # Scan as regular file
                            file_source = File(
                                content=entry_file,
                                path=inner_path,
                                config=config,
                                outer_paths=new_outer_paths,
                                max_archive_depth=max_archive_depth,
                                archive_depth=archive_depth + 1,
                            )

                            await file_source.fragments(yield_func)

                except Exception as e:
                    logger.warning("error extracting archive entry", path=virtual_path, error=str(e))
                    continue

    except Exception as e:
        logger.error("error reading tar archive", path=path, error=str(e))


async def scan_compressed_file(
    reader: BinaryIO,
    path: str,
    archive_type: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """
    Scan a single compressed file (gzip, bzip2, xz, zstd).

    Args:
        reader: Binary reader for the compressed file
        path: Path to the compressed file
        archive_type: Type of compression (gzip, bzip2, xz, zstd)
        config: Gitleaks configuration
        outer_paths: List of container archive paths
        max_archive_depth: Maximum nesting depth allowed
        archive_depth: Current nesting depth
        yield_func: Callback to process fragments
    """
    logger = get_logger()

    try:
        # Decompress based on type
        if archive_type == 'gzip':
            decompressed = gzip.GzipFile(fileobj=reader)
        elif archive_type == 'bzip2':
            decompressed = bz2.BZ2File(reader)
        elif archive_type == 'xz':
            decompressed = lzma.LZMAFile(reader)
        elif archive_type == 'zstd':
            if not HAS_ZSTD:
                logger.warning("zstandard library not available, skipping", path=path)
                return
            dctx = zstandard.ZstdDecompressor()
            decompressed = dctx.stream_reader(reader)
        else:
            logger.error("unknown compression type", path=path, type=archive_type)
            return

        with decompressed:
            # Import File here to avoid circular import
            from .file import File

            # Determine inner path (remove compression extension)
            inner_path = path
            for ext in ['.gz', '.bz2', '.xz', '.zst']:
                if inner_path.endswith(ext):
                    inner_path = inner_path[:-len(ext)]
                    break

            # Check if decompressed content is another archive
            inner_archive_type = detect_archive_type(inner_path)

            if inner_archive_type and archive_depth + 1 <= max_archive_depth:
                # Recursively scan nested archive
                new_outer_paths = outer_paths + [normalize_path(path)]
                logger.debug(
                    "scanning nested archive after decompression",
                    path=inner_path,
                    depth=archive_depth + 1
                )

                await scan_archive(
                    decompressed,
                    inner_path,
                    inner_archive_type,
                    config,
                    new_outer_paths,
                    max_archive_depth,
                    archive_depth + 1,
                    yield_func
                )
            else:
                # Scan as regular file
                file_source = File(
                    content=decompressed,
                    path=inner_path,
                    config=config,
                    outer_paths=outer_paths + [normalize_path(path)],
                    max_archive_depth=max_archive_depth,
                    archive_depth=archive_depth + 1,
                )

                await file_source.fragments(yield_func)

    except Exception as e:
        logger.error("error decompressing file", path=path, error=str(e))


async def scan_7z_archive(
    reader: BinaryIO,
    path: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """
    Scan a 7z archive, extracting and processing each file.

    Args:
        reader: Binary reader for the archive
        path: Path to the archive
        config: Gitleaks configuration
        outer_paths: List of container archive paths
        max_archive_depth: Maximum nesting depth allowed
        archive_depth: Current nesting depth
        yield_func: Callback to process fragments
    """
    logger = get_logger()

    if not HAS_7Z:
        logger.warning("py7zr library not available, skipping 7z file", path=path)
        return

    try:
        # 7z requires seekable file, write to temp file if needed
        if not hasattr(reader, 'seek'):
            # Write to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.7z') as tmp_file:
                tmp_file.write(reader.read())
                tmp_path = tmp_file.name

            try:
                with py7zr.SevenZipFile(tmp_path, 'r') as archive:
                    await _process_7z_archive(
                        archive, path, config, outer_paths,
                        max_archive_depth, archive_depth, yield_func
                    )
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        else:
            with py7zr.SevenZipFile(reader, 'r') as archive:
                await _process_7z_archive(
                    archive, path, config, outer_paths,
                    max_archive_depth, archive_depth, yield_func
                )

    except Exception as e:
        logger.error("error reading 7z archive", path=path, error=str(e))


async def _process_7z_archive(
    archive: 'py7zr.SevenZipFile',
    path: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """Helper function to process a 7z archive."""
    logger = get_logger()

    # Get list of files in the archive
    file_list = archive.list()

    for file_info in file_list:
        # Extract filename and check if it's a directory
        name = file_info.filename
        if file_info.is_directory:
            continue

        # Build virtual path
        inner_path = normalize_path(name)
        new_outer_paths = outer_paths + [normalize_path(path)]
        virtual_path = "!".join(new_outer_paths + [inner_path])

        # Check allowlist
        if should_skip_path(config, virtual_path):
            logger.debug("skipping archive entry: global allowlist", path=virtual_path)
            continue

        try:
            # Extract specific file
            extracted = archive.read([name])
            if name not in extracted:
                continue

            file_data = extracted[name]

            # Import File here to avoid circular import
            from .file import File

            # Create BytesIO for the extracted data
            entry_file = io.BytesIO(file_data.read() if hasattr(file_data, 'read') else file_data)

            # Check if this entry is itself an archive
            archive_type = detect_archive_type(inner_path)

            if archive_type and archive_depth + 1 <= max_archive_depth:
                # Recursively scan nested archive
                logger.debug(
                    "scanning nested archive",
                    path=virtual_path,
                    depth=archive_depth + 1
                )

                await scan_archive(
                    entry_file,
                    inner_path,
                    archive_type,
                    config,
                    new_outer_paths,
                    max_archive_depth,
                    archive_depth + 1,
                    yield_func
                )
            else:
                # Scan as regular file
                file_source = File(
                    content=entry_file,
                    path=inner_path,
                    config=config,
                    outer_paths=new_outer_paths,
                    max_archive_depth=max_archive_depth,
                    archive_depth=archive_depth + 1,
                )

                await file_source.fragments(yield_func)

        except Exception as e:
            logger.warning("error extracting 7z entry", path=virtual_path, error=str(e))
            continue


async def scan_rar_archive(
    reader: BinaryIO,
    path: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """
    Scan a RAR archive, extracting and processing each file.

    Args:
        reader: Binary reader for the archive
        path: Path to the archive
        config: Gitleaks configuration
        outer_paths: List of container archive paths
        max_archive_depth: Maximum nesting depth allowed
        archive_depth: Current nesting depth
        yield_func: Callback to process fragments
    """
    logger = get_logger()

    if not HAS_RAR:
        logger.warning("rarfile library not available, skipping rar file", path=path)
        return

    try:
        # RAR requires seekable file or file path, write to temp file
        if not hasattr(reader, 'name'):
            # Write to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.rar') as tmp_file:
                tmp_file.write(reader.read())
                tmp_path = tmp_file.name

            try:
                with rarfile.RarFile(tmp_path, 'r') as archive:
                    await _process_rar_archive(
                        archive, path, config, outer_paths,
                        max_archive_depth, archive_depth, yield_func
                    )
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        else:
            with rarfile.RarFile(reader, 'r') as archive:
                await _process_rar_archive(
                    archive, path, config, outer_paths,
                    max_archive_depth, archive_depth, yield_func
                )

    except Exception as e:
        logger.error("error reading rar archive", path=path, error=str(e))


async def _process_rar_archive(
    archive: 'rarfile.RarFile',
    path: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """Helper function to process a RAR archive."""
    logger = get_logger()

    for info in archive.infolist():
        # Skip directories
        if info.is_dir():
            continue

        # Build virtual path
        inner_path = normalize_path(info.filename)
        new_outer_paths = outer_paths + [normalize_path(path)]
        virtual_path = "!".join(new_outer_paths + [inner_path])

        # Check allowlist
        if should_skip_path(config, virtual_path):
            logger.debug("skipping archive entry: global allowlist", path=virtual_path)
            continue

        try:
            # Extract file
            with archive.open(info) as entry_file:
                # Import File here to avoid circular import
                from .file import File

                # Check if this entry is itself an archive
                archive_type = detect_archive_type(inner_path)

                if archive_type and archive_depth + 1 <= max_archive_depth:
                    # Recursively scan nested archive
                    logger.debug(
                        "scanning nested archive",
                        path=virtual_path,
                        depth=archive_depth + 1
                    )

                    await scan_archive(
                        entry_file,
                        inner_path,
                        archive_type,
                        config,
                        new_outer_paths,
                        max_archive_depth,
                        archive_depth + 1,
                        yield_func
                    )
                else:
                    # Scan as regular file
                    file_source = File(
                        content=entry_file,
                        path=inner_path,
                        config=config,
                        outer_paths=new_outer_paths,
                        max_archive_depth=max_archive_depth,
                        archive_depth=archive_depth + 1,
                    )

                    await file_source.fragments(yield_func)

        except Exception as e:
            logger.warning("error extracting rar entry", path=virtual_path, error=str(e))
            continue


async def scan_archive(
    reader: BinaryIO,
    path: str,
    archive_type: str,
    config: Optional[Config],
    outer_paths: list[str],
    max_archive_depth: int,
    archive_depth: int,
    yield_func: FragmentsFunc
) -> None:
    """
    Scan an archive file, dispatching to the appropriate handler.

    Args:
        reader: Binary reader for the archive
        path: Path to the archive
        archive_type: Type of archive detected
        config: Gitleaks configuration
        outer_paths: List of container archive paths
        max_archive_depth: Maximum nesting depth allowed
        archive_depth: Current nesting depth
        yield_func: Callback to process fragments
    """
    logger = get_logger()

    # Check depth limit
    if archive_depth + 1 > max_archive_depth:
        logger.debug(
            "skipping archive: max depth reached",
            path=path,
            depth=archive_depth,
            max_depth=max_archive_depth
        )
        return

    # Dispatch to appropriate handler
    if archive_type == 'zip':
        await scan_zip_archive(reader, path, config, outer_paths, max_archive_depth, archive_depth, yield_func)

    elif archive_type in ('tar', 'tar.gz', 'tar.bz2', 'tar.xz', 'tar.zst'):
        await scan_tar_archive(reader, path, archive_type, config, outer_paths, max_archive_depth, archive_depth, yield_func)

    elif archive_type in ('gzip', 'bzip2', 'xz', 'zstd'):
        await scan_compressed_file(reader, path, archive_type, config, outer_paths, max_archive_depth, archive_depth, yield_func)

    elif archive_type == '7z':
        await scan_7z_archive(reader, path, config, outer_paths, max_archive_depth, archive_depth, yield_func)

    elif archive_type == 'rar':
        await scan_rar_archive(reader, path, config, outer_paths, max_archive_depth, archive_depth, yield_func)

    else:
        logger.warning("unsupported archive type", path=path, type=archive_type)
