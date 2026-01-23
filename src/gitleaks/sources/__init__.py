"""
Source providers for gitleaks.

This module defines the Source protocol and common types for yielding content
fragments from different sources (git repositories, directories, stdin, archives).

All source implementations must conform to the Source protocol, which provides
a unified interface for the detection engine to consume content fragments.
"""

from collections.abc import Callable, AsyncIterator
from typing import Protocol, Optional

from .fragment import Fragment, CommitInfo, RemoteInfo


# Type alias for the callback function used to yield fragments
# The callback receives a Fragment and an optional error, and should return an error
# if processing should stop
FragmentsFunc = Callable[[Fragment, Optional[Exception]], Optional[Exception]]


class Source(Protocol):
    """
    Protocol for content sources that can yield fragments for scanning.

    All source implementations (directory, git, stdin, archive) must implement
    this protocol to provide a consistent interface for the detection engine.

    The Fragments method is similar to filepath.WalkDir in Go - it walks through
    the source and calls the yield callback for each fragment of content found.
    The callback can return an error to stop iteration early.
    """

    async def fragments(self, yield_func: FragmentsFunc) -> None:
        """
        Iterate through the source and yield content fragments.

        This method walks through the source (files, commits, stdin, etc.)
        and calls yield_func for each fragment of content to be scanned.

        Args:
            yield_func: Callback function to process each fragment.
                       Should return an exception to stop iteration, or None to continue.

        Raises:
            Exception: If an error occurs during fragment generation or if
                      yield_func returns an exception.

        Example:
            def process_fragment(fragment: Fragment, err: Optional[Exception]) -> Optional[Exception]:
                if err:
                    return err
                # Process fragment...
                return None

            await source.fragments(process_fragment)
        """
        ...


__all__ = [
    "Fragment",
    "CommitInfo",
    "RemoteInfo",
    "FragmentsFunc",
    "Source",
]
