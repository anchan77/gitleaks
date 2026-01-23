"""
Reader utilities for detecting secrets from streams.

This module provides deprecated wrapper functions for scanning io streams.
In the Python implementation, these are superseded by the sources.File class
and the Detector.detect_source() method.

These functions are maintained for backwards compatibility but may be removed
in a future version.
"""

from typing import BinaryIO, List, AsyncIterator, Tuple, Optional, TYPE_CHECKING
import asyncio
import io

from gitleaks.reporting.finding import Finding
from gitleaks.sources.file import File
from gitleaks.sources.fragment import Fragment

if TYPE_CHECKING:
    from gitleaks.detector.engine import Detector


async def detect_reader(
    detector: "Detector",
    reader: BinaryIO,
    buffer_size_kb: int = 64
) -> List[Finding]:
    """
    Detect secrets from a binary stream.

    This is a deprecated convenience function that wraps sources.File.
    Prefer using sources.File directly with Detector.detect_source().

    Args:
        detector: The Detector instance to use
        reader: Binary stream to read from
        buffer_size_kb: Buffer size in kilobytes (default: 64)

    Returns:
        List of findings detected in the stream

    Deprecated:
        Use sources.File with Detector.detect_source() instead
    """
    findings: List[Finding] = []
    pending_tasks: List[asyncio.Task] = []

    # Create a File source with the provided buffer size
    # File.fragments() can handle any reader with read() method
    file = File(
        content=reader,  # type: ignore
        path="",  # Empty path for reader-based detection
        buffer_size=1000 * buffer_size_kb,  # Convert KB to bytes
        config=detector.config,
        max_archive_depth=detector.max_archive_depth
    )

    # Process fragments and collect findings
    # Note: File.fragments expects a sync callback, but we need async detection
    # So we collect tasks and await them after
    def process_fragment(fragment: Fragment, error: Optional[Exception]) -> Optional[Exception]:
        if error:
            return error

        # Create a task for async detection
        task = asyncio.create_task(detector._detect_fragment(fragment))
        pending_tasks.append(task)

        return None

    # Run the fragments processing
    await file.fragments(process_fragment)

    # Wait for all detection tasks to complete
    if pending_tasks:
        results = await asyncio.gather(*pending_tasks)
        for fragment_findings in results:
            findings.extend(fragment_findings)

    return findings


async def stream_detect_reader(
    detector: "Detector",
    reader: BinaryIO,
    buffer_size_kb: int = 64
) -> Tuple[AsyncIterator[Finding], asyncio.Future[Optional[Exception]]]:
    """
    Stream detection results from a binary stream.

    This is a deprecated convenience function. Findings are yielded as soon
    as they are detected, allowing for immediate processing.

    Args:
        detector: The Detector instance to use
        reader: Binary stream to read from
        buffer_size_kb: Buffer size in kilobytes (default: 64)

    Returns:
        Tuple of:
            - AsyncIterator yielding findings as they are detected
            - Future that will contain final error (or None on success)

    Example:
        >>> findings_iter, error_future = await stream_detect_reader(detector, stream, 64)
        >>> async for finding in findings_iter:
        ...     print(f"Found: {finding.rule_id}")
        >>> error = await error_future
        >>> if error:
        ...     print(f"Error: {error}")

    Deprecated:
        Use sources.File.fragments() with async iteration instead
    """
    # Create queue for findings
    findings_queue: asyncio.Queue[Optional[Finding]] = asyncio.Queue()
    error_future: asyncio.Future[Optional[Exception]] = asyncio.Future()

    # Create a File source
    # File.fragments() can handle any reader with read() method
    file = File(
        content=reader,  # type: ignore
        path="",
        buffer_size=1000 * buffer_size_kb,
        config=detector.config,
        max_archive_depth=detector.max_archive_depth
    )

    # Background task to process fragments
    async def process_fragments():
        try:
            pending_tasks: List[asyncio.Task] = []

            def process_fragment(fragment: Fragment, error: Optional[Exception]) -> Optional[Exception]:
                if error:
                    return error

                # Create task for async detection and queue results
                async def detect_and_queue():
                    fragment_findings = await detector._detect_fragment(fragment)
                    for finding in fragment_findings:
                        await findings_queue.put(finding)

                task = asyncio.create_task(detect_and_queue())
                pending_tasks.append(task)

                return None

            await file.fragments(process_fragment)

            # Wait for all detection tasks to complete
            if pending_tasks:
                await asyncio.gather(*pending_tasks)

            error_future.set_result(None)
        except Exception as e:
            error_future.set_result(e)
        finally:
            # Signal end of findings
            await findings_queue.put(None)

    # Start background task
    asyncio.create_task(process_fragments())

    # Create async iterator for findings
    async def findings_iterator() -> AsyncIterator[Finding]:
        while True:
            finding = await findings_queue.get()
            if finding is None:
                break
            yield finding

    return findings_iterator(), error_future
