# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest import mock

from lib.ssdlc import SSDLCEvent, log_ssdlc_event


class TestSSDLC(unittest.TestCase):
    """Tests for SSDLC security event logging."""

    @mock.patch("lib.ssdlc.logger")
    @mock.patch("lib.ssdlc.datetime")
    def test_log_user_created(self, mock_datetime, mock_logger):
        mock_now = mock.MagicMock()
        mock_now.isoformat.return_value = "2025-01-01T12:00:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        log_ssdlc_event(SSDLCEvent.USER_CREATED, "alice")

        logged = mock_logger.warning.call_args[0][0]
        assert logged["event"] == "user_created:alice"
        assert logged["level"] == "WARN"
        assert logged["appid"] == "charm.local-users"
        assert logged["datetime"] == "2025-01-01T12:00:00+00:00"
        assert logged["description"] == "User created: alice"

    @mock.patch("lib.ssdlc.logger")
    @mock.patch("lib.ssdlc.datetime")
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

    @mock.patch("lib.ssdlc.logger")
    @mock.patch("lib.ssdlc.datetime")
    def test_log_event_with_additional_message(self, mock_datetime, mock_logger):
        mock_now = mock.MagicMock()
        mock_now.isoformat.return_value = "2025-01-01T12:00:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        log_ssdlc_event(SSDLCEvent.USER_CREATED, "carol", "SSH keys updated")

        logged = mock_logger.warning.call_args[0][0]
        assert logged["description"] == "User created: carol SSH keys updated"
