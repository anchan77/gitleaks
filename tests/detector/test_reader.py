"""
Tests for detector.reader module.

These tests verify the deprecated reader functions that wrap sources.File
functionality for backward compatibility.
"""

import io
import pytest
from unittest.mock import AsyncMock

from gitleaks.detector.engine import Detector
from gitleaks.detector.reader import detect_reader, stream_detect_reader
from gitleaks.config.models import Config, Rule


# AWS access key secret used in tests
SECRET = "AKIAIRYLJVKMPEGZMPJS"


class MockReader:
    """Mock reader that simulates EOF behavior."""

    def __init__(self, data: bytes, error_on_read: Exception = None):
        self.data = data
        self.read_count = 0
        self.error_on_read = error_on_read
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if self.read_count > 0:
            return b""  # EOF

        self.read_count += 1
        if self.error_on_read:
            raise self.error_on_read
        return self.data

    def read1(self, size: int = -1) -> bytes:
        return self.read(size)

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        self.closed = True


class TestDetectReader:
    """Tests for detect_reader function."""

    @pytest.mark.asyncio
    async def test_reader_with_string_reader(self):
        """Test detect_reader with strings.NewReader equivalent (io.BytesIO)."""
        # Create detector with AWS key rule
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key",
                tags=["key", "AWS"]
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Test with BytesIO (equivalent to strings.NewReader)
        reader = io.BytesIO(SECRET.encode())
        findings = await detect_reader(detector, reader, buffer_size_kb=10)

        assert len(findings) == 1
        assert findings[0].rule_id == "aws-access-key"
        assert findings[0].secret == SECRET

    @pytest.mark.asyncio
    async def test_reader_with_eof_error(self):
        """Test detect_reader when reader returns EOF along with bytes."""
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Mock reader that returns bytes and EOF
        reader = MockReader(SECRET.encode())
        findings = await detect_reader(detector, reader, buffer_size_kb=10)

        assert len(findings) == 1
        assert findings[0].secret == SECRET


class TestStreamDetectReader:
    """Tests for stream_detect_reader function."""

    @pytest.mark.asyncio
    async def test_single_secret_streaming(self):
        """Test streaming detection with a single secret."""
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        reader = io.BytesIO(SECRET.encode())
        findings_iter, error_future = await stream_detect_reader(
            detector, reader, buffer_size_kb=10
        )

        findings = []
        async for finding in findings_iter:
            findings.append(finding)

        error = await error_future

        assert error is None
        assert len(findings) == 1
        assert findings[0].secret == SECRET

    @pytest.mark.asyncio
    async def test_empty_reader_streaming(self):
        """Test streaming detection with empty reader."""
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        reader = io.BytesIO(b"")
        findings_iter, error_future = await stream_detect_reader(
            detector, reader, buffer_size_kb=10
        )

        findings = []
        async for finding in findings_iter:
            findings.append(finding)

        error = await error_future

        assert error is None
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_multiple_secrets_streaming(self):
        """Test streaming detection with multiple secrets."""
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Two secrets separated by newline
        content = f"{SECRET}\n{SECRET}".encode()
        reader = io.BytesIO(content)
        findings_iter, error_future = await stream_detect_reader(
            detector, reader, buffer_size_kb=20
        )

        findings = []
        async for finding in findings_iter:
            findings.append(finding)

        error = await error_future

        assert error is None
        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_mock_reader_with_eof_streaming(self):
        """Test streaming with mock reader that returns EOF."""
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        reader = MockReader(SECRET.encode())
        findings_iter, error_future = await stream_detect_reader(
            detector, reader, buffer_size_kb=10
        )

        findings = []
        async for finding in findings_iter:
            findings.append(finding)

        error = await error_future

        assert error is None
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_secret_split_across_boundary(self):
        """Test streaming when secret might be split across buffer boundaries."""
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Use small buffer to potentially split secret
        reader = io.BytesIO(SECRET.encode())
        findings_iter, error_future = await stream_detect_reader(
            detector, reader, buffer_size_kb=1  # 1KB buffer
        )

        findings = []
        async for finding in findings_iter:
            findings.append(finding)

        error = await error_future

        assert error is None
        assert len(findings) == 1
        assert findings[0].secret == SECRET

    @pytest.mark.asyncio
    async def test_reader_error_handling(self):
        """Test streaming when reader returns an error."""
        rules = [
            Rule(
                id="aws-access-key",
                regex=r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
                description="AWS Access Key"
            )
        ]
        config = Config(rules=rules)
        detector = Detector(config)

        # Create a mock reader that raises an error
        reader = MockReader(SECRET.encode(), error_on_read=IOError("simulated read error"))
        findings_iter, error_future = await stream_detect_reader(
            detector, reader, buffer_size_kb=10
        )

        findings = []
        async for finding in findings_iter:
            findings.append(finding)

        error = await error_future

        # Should have an error
        assert error is not None
        assert "simulated read error" in str(error) or "IOError" in str(type(error))
