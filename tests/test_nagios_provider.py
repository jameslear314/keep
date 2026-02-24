"""
Tests for the Nagios provider.

Covers webhook formatting (_format_alert), state mapping, notification
type handling, alerts_mock compatibility, and provider metadata.
"""

from keep.api.models.alert import AlertSeverity, AlertStatus
from keep.providers.nagios_provider.nagios_provider import NagiosProvider

# --- Webhook (_format_alert) tests ---


class TestNagiosFormatAlert:
    """Tests for _format_alert (webhook path)."""

    def test_service_critical(self):
        event = {
            "type": "SERVICE",
            "notification_type": "PROBLEM",
            "hostname": "web-01",
            "host_address": "10.0.0.1",
            "service_desc": "HTTP",
            "service_display_name": "HTTP Service",
            "service_state": "CRITICAL",
            "service_output": "Connection refused",
            "long_service_output": "Details here",
            "timestamp": "Mon Feb 24 10:00:00 UTC 2026",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.FIRING.value
        assert alert.severity == AlertSeverity.CRITICAL.value
        assert alert.hostname == "web-01"
        assert alert.service_desc == "HTTP"
        assert alert.description == "Connection refused"
        assert alert.long_output == "Details here"
        assert alert.source == ["nagios"]
        assert alert.id == "web-01_HTTP"

    def test_service_warning(self):
        event = {
            "type": "SERVICE",
            "notification_type": "PROBLEM",
            "hostname": "db-01",
            "service_desc": "Disk",
            "service_state": "WARNING",
            "service_output": "85% full",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.FIRING.value
        assert alert.severity == AlertSeverity.WARNING.value

    def test_service_unknown(self):
        event = {
            "type": "SERVICE",
            "notification_type": "PROBLEM",
            "hostname": "app-01",
            "service_desc": "Check",
            "service_state": "UNKNOWN",
            "service_output": "Plugin timeout",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.FIRING.value
        assert alert.severity == AlertSeverity.INFO.value

    def test_service_recovery(self):
        event = {
            "type": "SERVICE",
            "notification_type": "RECOVERY",
            "hostname": "web-01",
            "service_desc": "HTTP",
            "service_state": "OK",
            "service_output": "HTTP OK - 200",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.RESOLVED.value
        assert alert.severity == AlertSeverity.INFO.value

    def test_host_down(self):
        event = {
            "type": "HOST",
            "notification_type": "PROBLEM",
            "hostname": "app-03",
            "host_address": "10.0.0.3",
            "host_display_name": "App Server 03",
            "host_state": "DOWN",
            "host_output": "PING CRITICAL - 100% packet loss",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.FIRING.value
        assert alert.severity == AlertSeverity.CRITICAL.value
        assert alert.hostname == "app-03"
        assert alert.name == "App Server 03"
        assert alert.id == "app-03_HOST"

    def test_host_unreachable(self):
        event = {
            "type": "HOST",
            "notification_type": "PROBLEM",
            "hostname": "switch-01",
            "host_state": "UNREACHABLE",
            "host_output": "Parent host down",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.FIRING.value
        assert alert.severity == AlertSeverity.WARNING.value

    def test_host_recovery(self):
        event = {
            "type": "HOST",
            "notification_type": "RECOVERY",
            "hostname": "app-03",
            "host_state": "UP",
            "host_output": "PING OK",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.RESOLVED.value
        assert alert.severity == AlertSeverity.INFO.value

    def test_acknowledgement(self):
        event = {
            "type": "HOST",
            "notification_type": "ACKNOWLEDGEMENT",
            "hostname": "app-03",
            "host_state": "DOWN",
            "host_output": "PING CRITICAL",
            "notification_author": "admin",
            "notification_comment": "Investigating",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.ACKNOWLEDGED.value
        assert alert.notification_author == "admin"
        assert alert.notification_comment == "Investigating"

    def test_downtime_start(self):
        event = {
            "type": "HOST",
            "notification_type": "DOWNTIMESTART",
            "hostname": "db-01",
            "host_state": "UP",
            "host_output": "Scheduled maintenance",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.SUPPRESSED.value

    def test_downtime_end(self):
        event = {
            "type": "HOST",
            "notification_type": "DOWNTIMEEND",
            "hostname": "db-01",
            "host_state": "UP",
            "host_output": "Maintenance complete",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.RESOLVED.value

    def test_flapping_start(self):
        event = {
            "type": "SERVICE",
            "notification_type": "FLAPPINGSTART",
            "hostname": "web-01",
            "service_desc": "HTTP",
            "service_state": "CRITICAL",
            "service_output": "State oscillating",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.FIRING.value

    def test_flapping_stop(self):
        event = {
            "type": "SERVICE",
            "notification_type": "FLAPPINGSTOP",
            "hostname": "web-01",
            "service_desc": "HTTP",
            "service_state": "OK",
            "service_output": "Stable",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.RESOLVED.value

    def test_defaults_to_service_when_no_type(self):
        event = {
            "hostname": "web-01",
            "service_desc": "HTTP",
            "service_state": "CRITICAL",
            "service_output": "Timeout",
        }
        alert = NagiosProvider._format_alert(event)
        # Should default to SERVICE type
        assert alert.service_desc == "HTTP"

    def test_defaults_to_problem_when_no_notification_type(self):
        event = {
            "type": "SERVICE",
            "hostname": "web-01",
            "service_desc": "HTTP",
            "service_state": "CRITICAL",
            "service_output": "Timeout",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.status == AlertStatus.FIRING.value

    def test_empty_event(self):
        """Empty webhook payload should not crash."""
        alert = NagiosProvider._format_alert({})
        assert alert is not None
        assert alert.source == ["nagios"]
        assert alert.name == "unknown"

    def test_host_display_name_fallback(self):
        """When host_display_name is absent, falls back to hostname."""
        event = {
            "type": "HOST",
            "notification_type": "PROBLEM",
            "hostname": "app-03",
            "host_state": "DOWN",
            "host_output": "Down",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.name == "app-03"

    def test_service_display_name_fallback(self):
        """When service_display_name is absent, falls back to service_desc."""
        event = {
            "type": "SERVICE",
            "notification_type": "PROBLEM",
            "hostname": "web-01",
            "service_desc": "HTTP",
            "service_state": "CRITICAL",
            "service_output": "Fail",
        }
        alert = NagiosProvider._format_alert(event)
        assert alert.name == "HTTP"


# --- State mapping tests ---


class TestNagiosStateMaps:
    """Verify all state map entries are correct."""

    def test_service_severity_map_completeness(self):
        """All Nagios service states have severity mappings."""
        for state in ["OK", "WARNING", "CRITICAL", "UNKNOWN"]:
            assert state in NagiosProvider.SERVICE_SEVERITY_MAP
        for state in ["0", "1", "2", "3"]:
            assert state in NagiosProvider.SERVICE_SEVERITY_MAP

    def test_service_status_map_completeness(self):
        for state in ["OK", "WARNING", "CRITICAL", "UNKNOWN"]:
            assert state in NagiosProvider.SERVICE_STATUS_MAP
        for state in ["0", "1", "2", "3"]:
            assert state in NagiosProvider.SERVICE_STATUS_MAP

    def test_host_severity_map_completeness(self):
        for state in ["UP", "DOWN", "UNREACHABLE"]:
            assert state in NagiosProvider.HOST_SEVERITY_MAP
        for state in ["0", "1", "2"]:
            assert state in NagiosProvider.HOST_SEVERITY_MAP

    def test_host_status_map_completeness(self):
        for state in ["UP", "DOWN", "UNREACHABLE"]:
            assert state in NagiosProvider.HOST_STATUS_MAP
        for state in ["0", "1", "2"]:
            assert state in NagiosProvider.HOST_STATUS_MAP

    def test_ok_is_resolved(self):
        assert NagiosProvider.SERVICE_STATUS_MAP["OK"] == AlertStatus.RESOLVED
        assert NagiosProvider.SERVICE_STATUS_MAP["0"] == AlertStatus.RESOLVED

    def test_up_is_resolved(self):
        assert NagiosProvider.HOST_STATUS_MAP["UP"] == AlertStatus.RESOLVED
        assert NagiosProvider.HOST_STATUS_MAP["0"] == AlertStatus.RESOLVED

    def test_critical_is_critical(self):
        assert NagiosProvider.SERVICE_SEVERITY_MAP["CRITICAL"] == AlertSeverity.CRITICAL
        assert NagiosProvider.SERVICE_SEVERITY_MAP["2"] == AlertSeverity.CRITICAL

    def test_down_is_critical(self):
        assert NagiosProvider.HOST_SEVERITY_MAP["DOWN"] == AlertSeverity.CRITICAL
        assert NagiosProvider.HOST_SEVERITY_MAP["1"] == AlertSeverity.CRITICAL

    def test_notification_type_map_completeness(self):
        expected = [
            "PROBLEM",
            "RECOVERY",
            "ACKNOWLEDGEMENT",
            "FLAPPINGSTART",
            "FLAPPINGSTOP",
            "FLAPPINGDISABLED",
            "DOWNTIMESTART",
            "DOWNTIMEEND",
            "DOWNTIMECANCELLED",
        ]
        for nt in expected:
            assert nt in NagiosProvider.NOTIFICATION_TYPE_MAP


# --- alerts_mock tests ---


class TestNagiosAlertsMock:
    """Verify alerts_mock.py is compatible with simulate_alert()."""

    def test_alerts_mock_format(self):
        from keep.providers.nagios_provider.alerts_mock import ALERTS

        assert isinstance(ALERTS, dict)
        for key, value in ALERTS.items():
            assert "payload" in value, f"Key '{key}' missing 'payload'"
            assert isinstance(value["payload"], dict)

    def test_alerts_mock_payloads_format_successfully(self):
        from keep.providers.nagios_provider.alerts_mock import ALERTS

        for key, value in ALERTS.items():
            alert = NagiosProvider._format_alert(value["payload"])
            assert alert is not None, f"Failed to format alert for key '{key}'"
            assert alert.source == ["nagios"]

    def test_alerts_mock_covers_host_and_service(self):
        from keep.providers.nagios_provider.alerts_mock import ALERTS

        types = set()
        for value in ALERTS.values():
            types.add(value["payload"].get("type", "SERVICE"))
        assert "HOST" in types
        assert "SERVICE" in types

    def test_alerts_mock_covers_problem_and_recovery(self):
        from keep.providers.nagios_provider.alerts_mock import ALERTS

        notification_types = set()
        for value in ALERTS.values():
            notification_types.add(value["payload"].get("notification_type"))
        assert "PROBLEM" in notification_types
        assert "RECOVERY" in notification_types


# --- Provider metadata tests ---


class TestNagiosProviderMetadata:
    def test_display_name(self):
        assert NagiosProvider.PROVIDER_DISPLAY_NAME == "Nagios"

    def test_tags(self):
        assert "alert" in NagiosProvider.PROVIDER_TAGS

    def test_category(self):
        assert "Monitoring" in NagiosProvider.PROVIDER_CATEGORY

    def test_fingerprint_fields(self):
        assert NagiosProvider.FINGERPRINT_FIELDS is not None
        assert len(NagiosProvider.FINGERPRINT_FIELDS) > 0

    def test_scopes_defined(self):
        assert len(NagiosProvider.PROVIDER_SCOPES) > 0
