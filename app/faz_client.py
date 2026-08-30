"""FortiAnalyzer JSON-RPC client — read-only health/status calls.

Authenticates with Authorization: Bearer <token>. This header, not
X-API-Key, is what FortiAnalyzer's /jsonrpc endpoint actually recognizes —
confirmed by direct curl comparison against the test appliance
(192.168.64.4) while debugging ansible/faz_log_search.yml: X-API-Key and
no-auth-header-at-all produced byte-identical "-11 No permission" errors,
while Authorization: Bearer returned real data.

login()/logout()/preflight()/get_sys_status() cover health/status calls;
build_filter_expression()/get_log_fields()/get_devices()/search_logs()
(ported from the Ansible playbook's Jinja filter-building and
submit->poll->fetch logic, plus a device-list lookup confirmed live
against 192.168.64.4) support the Phase 3 Log Search tab.
"""

import datetime
import re
import time
from zoneinfo import ZoneInfo

import requests
import urllib3

from app.log_search_filters import FilterValidationError

_EXTRA_FILTER_OP_WHITELIST = {"==", "!="}
_EXTRA_FILTER_FIELD_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


class FAZError(Exception):
    """Raised when FortiAnalyzer returns a non-zero status code, a JSON-RPC
    error envelope, or an unexpected response shape."""


class FAZSearchTimeout(FAZError):
    """Raised when a log search doesn't reach 100% within the configured timeout."""


def summarize_connection_error(exc: Exception) -> str:
    """Collapse a raw requests/urllib3 exception into a short, UI-friendly
    label. The full exception text still belongs in the app log."""
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "Connection timed out"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS/SSL error"
    if isinstance(exc, requests.exceptions.ConnectionError):
        if "Connection refused" in str(exc):
            return "Connection refused"
        if "Name or service not known" in str(exc) or "nodename nor servname" in str(exc):
            return "DNS resolution failed"
        return "Unable to connect"
    if isinstance(exc, requests.exceptions.Timeout):
        return "Request timed out"
    return "Connection failed"


class FAZClient:
    def __init__(
        self,
        host: str,
        token: str,
        adom: str = "root",
        verify_ssl: bool = True,
        timeout: int = 30,
        port: int = 443,
        preflight_resource: str | None = None,
    ):
        self.host = host
        self.port = port
        self.token = token
        self.adom = adom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.preflight_resource = preflight_resource or f"/logview/adom/{adom}/logfields"
        self.base_url = f"https://{host}:{port}/jsonrpc"
        self._req_id = 0
        self._http = requests.Session()
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _post(self, body: dict) -> dict:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        resp = self._http.post(
            self.base_url,
            json=body,
            headers=headers,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _unwrap_result(data: dict) -> dict:
        if "error" in data:
            raise FAZError(f"FortiAnalyzer error: {data['error']}")
        result = data.get("result")
        if isinstance(result, list):
            result = result[0] if result else {}
        if not isinstance(result, dict):
            raise FAZError(f"Unexpected FortiAnalyzer response shape: {data!r}")
        # Confirmed live against 192.168.64.4: only some resources (e.g.
        # /sys/status) nest a "status" field in their result item. Others
        # (e.g. /logview/adom/<adom>/logfields) return a bare {"data": [...]}
        # with no "status" key at all — its absence means success, not
        # failure, so it must not be treated as an implicit error code.
        status = result.get("status")
        if status is not None and status.get("code", 0) != 0:
            raise FAZError(status.get("message", "Unknown FortiAnalyzer error"))
        return result

    def login(self) -> "FAZClient":
        # Bearer token auth — no session login call needed.
        return self

    def logout(self) -> None:
        self._http.close()

    def __enter__(self) -> "FAZClient":
        return self.login()

    def __exit__(self, *_exc) -> None:
        self.logout()

    def preflight(self) -> bool:
        """Connectivity/permission check against the logview module.

        Ported from the Ansible playbook's preflight task
        (ansible/faz_log_search.yml). Returns True if the account can read
        logview resources; raises FAZError otherwise — most commonly with
        status code -11 "No permission for the resource".
        """
        body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "get",
            "params": [
                {
                    "url": self.preflight_resource,
                    "apiver": 3,
                    "devtype": "FortiGate",
                    "logtype": "traffic",
                }
            ],
            "session": None,
        }
        self._unwrap_result(self._post(body))
        return True

    def get_log_fields(self, logtype: str = "traffic", devtype: str = "FortiGate") -> list[dict]:
        """Field list for a logtype, from the same logview/logfields resource
        preflight() already probes. Confirmed live against 192.168.64.4: the
        response is a bare {"data": [{"field": [...]}]} with no "status" key
        (see _unwrap_result's handling of that)."""
        body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "get",
            "params": [
                {
                    "url": self.preflight_resource,
                    "apiver": 3,
                    "devtype": devtype,
                    "logtype": logtype,
                }
            ],
            "session": None,
        }
        result = self._unwrap_result(self._post(body))
        data = result.get("data", [])
        if isinstance(data, list) and data and "field" in data[0]:
            return data[0]["field"]
        return []

    def get_devices(self) -> list[dict]:
        """Cheap device list for the ADOM, from /dvmdb/adom/<adom>/device.

        Confirmed live against 192.168.64.4: this resource (distinct from
        /dvm/adom/<adom>/device, which errors "URI /dvm/device not
        supported") returns each managed device's full DVM record,
        including sensitive fields (adm_pass, private_key). Only the
        fields needed for the Log Search device picker are extracted here
        — devid uses the device's serial number ("sn"), which is what
        search_logs()'s device param actually expects; the human-readable
        "name" alone is rejected by /logview/adom/<adom>/logsearch with
        "None of the device(s) can be found under the adom". Devices with
        no "sn" are skipped entirely — they have no usable devid and would
        otherwise show up as a picker entry that fails every search."""
        body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "get",
            "params": [{"url": f"/dvmdb/adom/{self.adom}/device"}],
            "session": None,
        }
        result = self._unwrap_result(self._post(body))
        data = result.get("data", [])
        return [
            {
                "devid": d.get("sn", ""),
                "name": d.get("name", ""),
                "platform": d.get("platform_str", ""),
            }
            for d in data
            if d.get("sn")
        ]

    def get_log_stats(self, adom: str | None = None) -> list[dict]:
        """Per-device log stats for the given ADOM (defaults to self.adom),
        from /logview/adom/<adom>/logstats. Returns one record per device,
        vdoms folded together: last_log_timestamp is the max (most recent)
        across the device's vdoms, lograte is their sum. A device with no
        vdoms (never logged) gets last_log_timestamp=None, lograte=0.0.

        Request/response shape confirmed against the vendored spec
        (api-info/.../logview.json, logview.logstats.get.{req,resp}) — not
        yet confirmed live against real hardware."""
        target_adom = adom or self.adom
        body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "get",
            "params": [{"url": f"/logview/adom/{target_adom}/logstats", "apiver": 3}],
            "session": None,
        }
        result = self._unwrap_result(self._post(body))
        devs = (result.get("data") or {}).get("devs") or []
        stats = []
        for dev in devs:
            vdoms = dev.get("vdoms") or []
            timestamps = [v.get("last-log-timestamp") for v in vdoms if v.get("last-log-timestamp")]
            stats.append(
                {
                    "devid": dev.get("devid", ""),
                    "devname": dev.get("devname", ""),
                    "last_log_timestamp": max(timestamps) if timestamps else None,
                    "lograte": sum(v.get("lograte", 0.0) for v in vdoms),
                }
            )
        return stats

    def local_time_range(self, start_iso: str, end_iso: str) -> tuple[str, str]:
        """Convert UTC ISO8601 start/end (what the browser sends) into the
        appliance's own configured timezone. FortiAnalyzer's logsearch
        time-range is interpreted in the appliance's local time, not UTC —
        confirmed live: an otherwise-valid filter with a UTC-based window
        landed in the appliance's "future" relative to its own clock and
        failed with a generic "-32603 Internal error" rather than a useful
        message. Falls back to returning the inputs unchanged (rather than
        failing the search) if the appliance's timezone can't be determined
        or the inputs aren't parseable ISO8601.
        """
        try:
            tz_name = self.get_sys_status().get("TZ")
            if not tz_name:
                return start_iso, end_iso
            tz = ZoneInfo(tz_name)

            def convert(value: str) -> str:
                dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt.astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S")

            return convert(start_iso), convert(end_iso)
        except Exception:
            return start_iso, end_iso

    def search_logs(
        self,
        logtype: str,
        device: str,
        filter_expression: str,
        start_time: str,
        end_time: str,
        limit: int = 1000,
        poll_interval: float = 2.0,
        timeout: float = 60.0,
    ) -> dict:
        """Submit a FAZ log search, poll until 100% or timeout, and return
        {"rows": [...], "fields": [...], "truncated": bool}. Ported from
        ansible/faz_log_search.yml's submit->poll->fetch loop, using the
        documented /logview/adom/<adom>/logsearch resource
        (api-info/.../logview.json) rather than the playbook's probed path."""
        submit_body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "add",
            "params": [
                {
                    "url": f"/logview/adom/{self.adom}/logsearch",
                    "apiver": 3,
                    "device": [{"devid": device}],
                    "filter": filter_expression,
                    "limit": limit,
                    "logtype": logtype,
                    "offset": 0,
                    "case-sensitive": False,
                    "time-order": "desc",
                    "time-range": {"start": start_time, "end": end_time},
                }
            ],
            "session": None,
        }
        submit_result = self._unwrap_result(self._post(submit_body))
        tid = submit_result.get("tid")
        if tid is None:
            raise FAZError(f"Log search submit returned no task ID: {submit_result!r}")

        fetch_url = f"/logview/adom/{self.adom}/logsearch/{tid}"
        deadline = time.monotonic() + timeout
        last_result: dict = {}
        while True:
            if time.monotonic() >= deadline:
                raise FAZSearchTimeout(
                    f"Log search did not complete within {timeout}s "
                    f"(last percentage={last_result.get('percentage', 0)})"
                )
            fetch_body = {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "get",
                "params": [{"url": fetch_url, "apiver": 3, "limit": limit, "offset": 0}],
                "session": None,
            }
            last_result = self._unwrap_result(self._post(fetch_body))
            if last_result.get("percentage", 0) >= 100:
                break
            time.sleep(poll_interval)

        rows = last_result.get("data", [])
        fields = sorted({key for row in rows for key in row}) if rows else []
        return_lines = last_result.get("return-lines", len(rows))
        return {
            "rows": rows,
            "fields": fields,
            "truncated": return_lines >= limit,
        }

    def get_sys_status(self) -> dict:
        """Return FortiAnalyzer /sys/status: hostname, version, serial, HA
        mode, disk usage. The exact field names in the returned dict are
        NOT covered by the Swagger specs in api-info/ (those only document
        logview/eventmgmt/fortiview) and must be validated live against
        the test appliance as part of this phase's validation step
        (Task 9) before the Dashboard is considered complete.
        """
        body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "get",
            "params": [{"url": "/sys/status"}],
            "session": None,
        }
        result = self._unwrap_result(self._post(body))
        return result.get("data", {})

    @staticmethod
    def build_filter_expression(
        source_clauses: list[str],
        destination_clauses: list[str],
        port_clauses: list[str],
        extra_filters: list[dict] | None = None,
    ) -> str:
        """Combine already-parsed clause fragments (see app/log_search_filters.py)
        into one FAZ filter expression. Entries within one group are OR'd
        together; the groups themselves are AND'd against each other."""
        groups: list[str] = []
        for clause_list in (source_clauses, destination_clauses, port_clauses):
            if clause_list:
                groups.append("(" + " or ".join(clause_list) + ")")
        for f in extra_filters or []:
            field = str(f.get("field", ""))
            op = str(f.get("op", ""))
            value = str(f.get("value", ""))
            if op not in _EXTRA_FILTER_OP_WHITELIST:
                raise FilterValidationError(
                    f"Invalid filter operator '{op}' for field '{field}': "
                    f"only == and != are allowed"
                )
            if not _EXTRA_FILTER_FIELD_RE.match(field):
                raise FilterValidationError(
                    f"Invalid filter field '{field}': only letters, digits, '_' and '-' are allowed"
                )
            if '"' in value:
                raise FilterValidationError(
                    f"Invalid filter value '{value}' for field '{field}': "
                    f'quote characters (") are not allowed'
                )
            quoted_value = value if value.lstrip("-").isdigit() else f'"{value}"'
            groups.append(f"({field}{op}{quoted_value})")
        return " and ".join(groups)
