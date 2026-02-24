"""
Nagios Provider for Keep.

Supports both Nagios XI (REST API with API key) and Nagios Core/XI
(webhook via custom notification commands).

- Pull: Fetches host and service status from the Nagios XI REST API.
- Push: Receives alerts via webhook from Nagios notification commands.
"""

import dataclasses

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope


@pydantic.dataclasses.dataclass
class NagiosProviderAuthConfig:
    """
    Authentication configuration for Nagios XI REST API.

    The API key can be found in Nagios XI under your username menu
    in the top-right corner of the web interface.
    """

    host_url: pydantic.AnyHttpUrl = dataclasses.field(
        metadata={
            "required": True,
            "description": "Nagios XI Host URL",
            "hint": "e.g. https://nagios.example.com/nagiosxi",
            "sensitive": False,
            "validation": "any_http_url",
        }
    )

    api_key: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "Nagios XI API Key (optional, for pulling alerts)",
            "hint": "Found under your username in Nagios XI",
            "sensitive": True,
        },
    )


class NagiosProvider(BaseProvider):
    """
    Get alerts from Nagios XI/Core into Keep.

    Supports:
    - Pulling alerts from Nagios XI via REST API (host and service status)
    - Receiving real-time alerts via webhook (Nagios notification commands)
    """

    webhook_documentation_here_differs_from_general_documentation = True
    webhook_description = ""
    webhook_template = ""
    webhook_markdown = """
To send alerts from Nagios to Keep, configure custom notification commands:

**1. Create a Host notification command in Nagios:**

```
define command {{
    command_name    keep_host_notification
    command_line    /usr/bin/curl -s -o /dev/null -X POST \\
        -H "Content-Type: application/json" \\
        -H "X-API-KEY: {api_key}" \\
        -d '{{"type":"HOST","notification_type":"$NOTIFICATIONTYPE$","hostname":"$HOSTNAME$","host_address":"$HOSTADDRESS$","host_display_name":"$HOSTDISPLAYNAME$","host_state":"$HOSTSTATE$","host_output":"$HOSTOUTPUT$","long_host_output":"$LONGHOSTOUTPUT$","timestamp":"$LONGDATETIME$","notification_author":"$NOTIFICATIONAUTHOR$","notification_comment":"$NOTIFICATIONCOMMENT$"}}' \\
        {keep_webhook_api_url}
}}
```

**2. Create a Service notification command in Nagios:**

```
define command {{
    command_name    keep_service_notification
    command_line    /usr/bin/curl -s -o /dev/null -X POST \\
        -H "Content-Type: application/json" \\
        -H "X-API-KEY: {api_key}" \\
        -d '{{"type":"SERVICE","notification_type":"$NOTIFICATIONTYPE$","hostname":"$HOSTNAME$","host_address":"$HOSTADDRESS$","service_desc":"$SERVICEDESC$","service_display_name":"$SERVICEDISPLAYNAME$","service_state":"$SERVICESTATE$","service_output":"$SERVICEOUTPUT$","long_service_output":"$LONGSERVICEOUTPUT$","timestamp":"$LONGDATETIME$","notification_author":"$NOTIFICATIONAUTHOR$","notification_comment":"$NOTIFICATIONCOMMENT$"}}' \\
        {keep_webhook_api_url}
}}
```

**3. Create a contact that uses these commands and assign it to your hosts/services.**

For detailed setup instructions, see [Keep documentation](https://docs.keephq.dev/providers/documentation/nagios-provider).
    """

    PROVIDER_DISPLAY_NAME = "Nagios"
    PROVIDER_TAGS = ["alert"]
    PROVIDER_CATEGORY = ["Monitoring"]
    FINGERPRINT_FIELDS = ["hostname", "service_desc"]

    PROVIDER_SCOPES = [
        ProviderScope(
            name="read_alerts",
            description="Read host and service status from Nagios XI",
        ),
    ]

    # Nagios service states (current_state field, string values)
    SERVICE_SEVERITY_MAP = {
        "0": AlertSeverity.INFO,  # OK
        "1": AlertSeverity.WARNING,  # WARNING
        "2": AlertSeverity.CRITICAL,  # CRITICAL
        "3": AlertSeverity.INFO,  # UNKNOWN
        # String state names (from webhooks)
        "OK": AlertSeverity.INFO,
        "WARNING": AlertSeverity.WARNING,
        "CRITICAL": AlertSeverity.CRITICAL,
        "UNKNOWN": AlertSeverity.INFO,
    }

    SERVICE_STATUS_MAP = {
        "0": AlertStatus.RESOLVED,  # OK
        "1": AlertStatus.FIRING,  # WARNING
        "2": AlertStatus.FIRING,  # CRITICAL
        "3": AlertStatus.FIRING,  # UNKNOWN
        # String state names (from webhooks)
        "OK": AlertStatus.RESOLVED,
        "WARNING": AlertStatus.FIRING,
        "CRITICAL": AlertStatus.FIRING,
        "UNKNOWN": AlertStatus.FIRING,
    }

    HOST_SEVERITY_MAP = {
        "0": AlertSeverity.INFO,  # UP
        "1": AlertSeverity.CRITICAL,  # DOWN
        "2": AlertSeverity.WARNING,  # UNREACHABLE
        # String state names (from webhooks)
        "UP": AlertSeverity.INFO,
        "DOWN": AlertSeverity.CRITICAL,
        "UNREACHABLE": AlertSeverity.WARNING,
    }

    HOST_STATUS_MAP = {
        "0": AlertStatus.RESOLVED,  # UP
        "1": AlertStatus.FIRING,  # DOWN
        "2": AlertStatus.FIRING,  # UNREACHABLE
        # String state names (from webhooks)
        "UP": AlertStatus.RESOLVED,
        "DOWN": AlertStatus.FIRING,
        "UNREACHABLE": AlertStatus.FIRING,
    }

    # Notification type to status mapping (for webhooks)
    NOTIFICATION_TYPE_MAP = {
        "PROBLEM": AlertStatus.FIRING,
        "RECOVERY": AlertStatus.RESOLVED,
        "ACKNOWLEDGEMENT": AlertStatus.ACKNOWLEDGED,
        "FLAPPINGSTART": AlertStatus.FIRING,
        "FLAPPINGSTOP": AlertStatus.RESOLVED,
        "FLAPPINGDISABLED": AlertStatus.RESOLVED,
        "DOWNTIMESTART": AlertStatus.SUPPRESSED,
        "DOWNTIMEEND": AlertStatus.RESOLVED,
        "DOWNTIMECANCELLED": AlertStatus.RESOLVED,
    }

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def dispose(self):
        pass

    def validate_config(self):
        self.authentication_config = NagiosProviderAuthConfig(
            **self.config.authentication
        )

    def validate_scopes(self) -> dict[str, bool | str]:
        self.logger.info("Validating Nagios XI provider scopes")
        if not self.authentication_config.api_key:
            # Webhook-only mode — no API scopes to validate
            return {"read_alerts": True}

        try:
            response = requests.get(
                url=f"{self.authentication_config.host_url}/api/v1/system/status",
                params={"apikey": self.authentication_config.api_key},
                verify=True,
            )

            if response.status_code == 200:
                self.logger.info("Nagios XI scope validation successful")
                return {"read_alerts": True}

            response.raise_for_status()

        except Exception as e:
            self.logger.exception("Failed to validate Nagios XI scopes")
            return {"read_alerts": str(e)}

    def _get_alerts(self) -> list[AlertDto]:
        self.logger.info("Getting alerts from Nagios XI")

        if not self.authentication_config.api_key:
            self.logger.info("No API key configured — webhook-only mode")
            return []

        alerts = []

        try:
            alerts.extend(self._get_host_alerts())
        except Exception as e:
            self.logger.error("Error getting host alerts from Nagios XI: %s", e)

        try:
            alerts.extend(self._get_service_alerts())
        except Exception as e:
            self.logger.error("Error getting service alerts from Nagios XI: %s", e)

        return alerts

    def _get_host_alerts(self) -> list[AlertDto]:
        response = requests.get(
            url=f"{self.authentication_config.host_url}/api/v1/objects/hoststatus",
            params={"apikey": self.authentication_config.api_key},
            verify=True,
        )

        if response.status_code != 200:
            response.raise_for_status()

        data = response.json()
        hosts = data.get("hoststatuslist", {}).get("hoststatus", [])

        # Handle single-object response (not wrapped in list)
        if isinstance(hosts, dict):
            hosts = [hosts]

        alerts = []
        for host in hosts:
            current_state = str(host.get("current_state", "0"))

            alert = AlertDto(
                id=host.get("host_object_id"),
                name=host.get("name", host.get("host_name")),
                hostname=host.get("name", host.get("host_name")),
                host_display_name=host.get("display_name"),
                host_address=host.get("address", host.get("host_address")),
                description=host.get("status_text", ""),
                status=self.HOST_STATUS_MAP.get(current_state, AlertStatus.FIRING),
                severity=self.HOST_SEVERITY_MAP.get(current_state, AlertSeverity.INFO),
                lastReceived=host.get("last_check"),
                last_state_change=host.get("last_state_change"),
                check_command=host.get("check_command"),
                current_check_attempt=host.get("current_check_attempt"),
                max_check_attempts=host.get("max_check_attempts"),
                state_type=host.get("state_type"),
                is_flapping=host.get("is_flapping"),
                acknowledged=host.get("problem_acknowledged", "0") != "0",
                scheduled_downtime_depth=host.get("scheduled_downtime_depth"),
                source=["nagios"],
            )
            alerts.append(alert)

        return alerts

    def _get_service_alerts(self) -> list[AlertDto]:
        response = requests.get(
            url=f"{self.authentication_config.host_url}/api/v1/objects/servicestatus",
            params={"apikey": self.authentication_config.api_key},
            verify=True,
        )

        if response.status_code != 200:
            response.raise_for_status()

        data = response.json()
        services = data.get("servicestatuslist", {}).get("servicestatus", [])

        # Handle single-object response (not wrapped in list)
        if isinstance(services, dict):
            services = [services]

        alerts = []
        for svc in services:
            current_state = str(svc.get("current_state", "0"))

            alert = AlertDto(
                id=svc.get("service_object_id"),
                name=svc.get("display_name", svc.get("name")),
                hostname=svc.get("host_name"),
                host_address=svc.get("host_address"),
                service_desc=svc.get("name"),
                description=svc.get("status_text", ""),
                long_output=svc.get("status_text_long"),
                status=self.SERVICE_STATUS_MAP.get(current_state, AlertStatus.FIRING),
                severity=self.SERVICE_SEVERITY_MAP.get(
                    current_state, AlertSeverity.INFO
                ),
                lastReceived=svc.get("last_check"),
                last_state_change=svc.get("last_state_change"),
                check_command=svc.get("check_command"),
                current_check_attempt=svc.get("current_check_attempt"),
                max_check_attempts=svc.get("max_check_attempts"),
                state_type=svc.get("state_type"),
                performance_data=svc.get("performance_data"),
                is_flapping=svc.get("is_flapping"),
                acknowledged=svc.get("problem_acknowledged", "0") != "0",
                scheduled_downtime_depth=svc.get("scheduled_downtime_depth"),
                source=["nagios"],
            )
            alerts.append(alert)

        return alerts

    @staticmethod
    def _parse_timestamp(ts: str | None) -> str | None:
        """Parse Nagios timestamp to ISO format. Returns None if unparseable."""
        if not ts:
            return None
        # Already ISO 8601 format (e.g., 2026-02-24T10:00:00Z)
        if len(ts) > 10 and ts[10] == "T":
            return ts
        # Nagios format: "Mon Feb 24 10:00:00 UTC 2026"
        try:
            from dateutil.parser import parse as dateutil_parse

            dt = dateutil_parse(ts)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except (ValueError, ImportError):
            return None

    @staticmethod
    def _format_alert(
        event: dict, provider_instance: "BaseProvider" = None
    ) -> AlertDto | list[AlertDto]:
        """
        Format a Nagios webhook notification payload into a Keep AlertDto.

        Handles both HOST and SERVICE notification types.
        """
        alert_type = event.get("type", "SERVICE").upper()
        notification_type = event.get("notification_type", "PROBLEM")

        # Determine status from notification_type first, then fall back to state
        status = NagiosProvider.NOTIFICATION_TYPE_MAP.get(
            notification_type, AlertStatus.FIRING
        )

        if alert_type == "HOST":
            host_state = event.get("host_state", "DOWN")
            severity = NagiosProvider.HOST_SEVERITY_MAP.get(
                host_state, AlertSeverity.CRITICAL
            )
            # Override status from state if not a special notification type
            if notification_type in ("PROBLEM", "RECOVERY"):
                status = NagiosProvider.HOST_STATUS_MAP.get(
                    host_state, AlertStatus.FIRING
                )

            hostname = event.get("hostname", "unknown")
            last_received = NagiosProvider._parse_timestamp(event.get("timestamp"))
            alert = AlertDto(
                id=f"{hostname}_HOST",
                name=event.get("host_display_name", event.get("hostname", "unknown")),
                hostname=hostname,
                host_address=event.get("host_address"),
                description=event.get("host_output", ""),
                long_output=event.get("long_host_output"),
                status=status,
                severity=severity,
                lastReceived=last_received,
                notification_type=notification_type,
                notification_author=event.get("notification_author"),
                notification_comment=event.get("notification_comment"),
                source=["nagios"],
            )
        else:
            # SERVICE notification
            service_state = event.get("service_state", "CRITICAL")
            severity = NagiosProvider.SERVICE_SEVERITY_MAP.get(
                service_state, AlertSeverity.CRITICAL
            )
            if notification_type in ("PROBLEM", "RECOVERY"):
                status = NagiosProvider.SERVICE_STATUS_MAP.get(
                    service_state, AlertStatus.FIRING
                )

            hostname = event.get("hostname", "unknown")
            service_desc = event.get("service_desc", "unknown")
            last_received = NagiosProvider._parse_timestamp(event.get("timestamp"))
            alert = AlertDto(
                id=f"{hostname}_{service_desc}",
                name=event.get(
                    "service_display_name",
                    event.get("service_desc", "unknown"),
                ),
                hostname=hostname,
                host_address=event.get("host_address"),
                service_desc=event.get("service_desc"),
                description=event.get("service_output", ""),
                long_output=event.get("long_service_output"),
                status=status,
                severity=severity,
                lastReceived=last_received,
                notification_type=notification_type,
                notification_author=event.get("notification_author"),
                notification_comment=event.get("notification_comment"),
                source=["nagios"],
            )

        return alert


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])

    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )

    import os

    nagios_host = os.environ.get("NAGIOS_HOST_URL")
    nagios_api_key = os.environ.get("NAGIOS_API_KEY")

    config = ProviderConfig(
        description="Nagios Provider",
        authentication={
            "host_url": nagios_host,
            "api_key": nagios_api_key,
        },
    )

    provider = NagiosProvider(context_manager, "nagios", config)
    alerts = provider._get_alerts()
    print(f"Got {len(alerts)} alerts")
    for alert in alerts:
        print(f"  {alert.hostname}: {alert.name} - {alert.status} ({alert.severity})")
