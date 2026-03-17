# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from datetime import datetime, timezone
from unittest import mock

from ssdlc import SSDLCEvent, log_ssdlc_event


class TestSSDLC(unittest.TestCase):
    """Tests for SSDLC security event logging."""

    @mock.patch("ssdlc.logger")
    @mock.patch("ssdlc.datetime")
    def test_log_user_created(self, mock_datetime, mock_logger):
        mock_now = mock.MagicMock()
        mock_now.isoformat.return_value = "2025-01-01T12:00:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        log_ssdlc_event(SSDLCEvent.USER_CREATED, "alice", "SSH keys added")

        logged = mock_logger.warning.call_args[0][0]
        assert logged["event"] == "user_created:alice"
        assert logged["level"] == "WARN"
        assert logged["appid"] == "charm.local-users"
        assert logged["datetime"] == "2025-01-01T12:00:00+00:00"
        assert logged["description"] == "User created: alice SSH keys added"

    @mock.patch("ssdlc.logger")
    @mock.patch("ssdlc.datetime")
    def test_log_user_updated(self, mock_datetime, mock_logger):
        mock_now = mock.MagicMock()
        mock_now.isoformat.return_value = "2025-01-01T12:00:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        log_ssdlc_event(SSDLCEvent.USER_UPDATED, "bob")

        logged = mock_logger.warning.call_args[0][0]
        assert logged["event"] == "user_updated:bob"
        assert logged["level"] == "WARN"
        assert logged["appid"] == "charm.local-users"
        assert logged["description"] == "User updated: bob"

    @mock.patch("ssdlc.logger")
    @mock.patch("ssdlc.datetime")
    def test_log_ssdlc_system_event_datetime_format(self, mock_datetime, mock_logger):
        """Test that datetime is in ISO 8601 format with timezone."""
        # Use a real datetime to test formatting
        test_time = datetime(2025, 1, 15, 14, 30, 45, tzinfo=timezone.utc)
        mock_datetime.now.return_value.astimezone.return_value = test_time

        log_ssdlc_event(SSDLCEvent.USER_DELETED, "charlie")

        logged = mock_logger.warning.call_args[0][0]
        # Verify ISO 8601 format with timezone
        assert logged["datetime"] == "2025-01-15T14:30:45+00:00"
        assert logged["event"] == "user_deleted:charlie"
        assert logged["level"] == "WARN"
        assert logged["description"] == "User deleted: charlie"
