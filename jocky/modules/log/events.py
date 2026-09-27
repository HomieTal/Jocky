"""log module: Windows Event Log forensics (read-only, manual §12.1).

collect log.windows_events(channel: "Security", event_id: 4625,
                           max: 200, within_hours: 24)

Reads events through `wevtutil qe <channel> /q:<XPath> /f:RenderedXml`
and parses the XML output. Common triage channels: Security, System,
Application, Microsoft-Windows-PowerShell/Operational.
"""

from __future__ import annotations

import datetime as _dt
import xml.etree.ElementTree as _ET
from typing import Any, Dict, List, Optional

from jocky.modules.base import CollectContext, Collector
from jocky.modules import winutil

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

_USER_FIELDS = ("TargetUserName", "SubjectUserName", "SamAccountName",
                "TargetDomainName", "AccountName")


class WindowsEventsCollector(Collector):
    module = "log"
    entity = "windows_events"
    title = "Windows Event Log"
    record_type = "event"
    fields = ["time", "channel", "event_id", "provider", "computer", "user",
              "level", "message", "keywords", "correlation_id"]
    columns = ["time", "event_id", "channel", "provider", "user", "level", "message"]
    arg_spec = {
        "channel": {"type": "str", "default": "Security"},
        "event_id": {"type": "str", "default": ""},
        "max": {"type": "int", "default": 200},
        "within_hours": {"type": "float", "default": 24.0},
    }

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        opts = self.resolve_args(args, kwargs)
        channel = str(opts["channel"] or "Security")
        max_events = int(opts["max"] or 200)
        within_hours = float(opts["within_hours"] or 0)
        event_ids = [s.strip() for s in str(opts["event_id"] or "").split(",")
                     if s.strip()]

        xpath = "*"
        if event_ids:
            inner = " or ".join(f"EventID={eid}" for eid in event_ids)
            xpath = f"*[System[({inner})]]"

        cmd = ["wevtutil", "qe", channel, f"/q:{xpath}", f"/c:{max_events}",
               "/rd:true", "/f:RenderedXml"]
        ctx.progress(f"querying {channel} event log (last {max_events} events)...")
        try:
            rc, out = winutil.run_capture(cmd, timeout=120)
        except Exception as exc:
            from jocky.runtime import errors
            raise errors.collect_failed(f"wevtutil failed: {exc}") from None
        if rc != 0:
            from jocky.runtime import errors
            hint = ""
            if "Security" in channel and "denied" in out.lower():
                hint = " — reading the Security channel requires Administrator"
            raise errors.collect_failed(
                f"wevtutil failed for channel '{channel}' (exit {rc}){hint}: "
                + out.strip()[:200]) from None

        records: List[Dict[str, Any]] = []
        cutoff = None
        if within_hours > 0:
            cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=within_hours)
        # wevtutil emits one <Event> doc per event; wrap and parse individually
        for chunk in out.split("<?xml"):
            if not chunk.strip():
                continue
            try:
                root = _ET.fromstring("<?xml" + chunk)
            except _ET.ParseError:
                continue
            rec = self._parse_event(root, channel)
            if rec is None:
                continue
            if cutoff is not None and rec["_dt"] is not None and rec["_dt"] < cutoff:
                continue
            rec.pop("_dt", None)
            records.append(rec)
        records.sort(key=lambda r: r.get("time") or "", reverse=True)
        return records

    def _parse_event(self, root: _ET.Element, channel: str) -> Optional[Dict[str, Any]]:
        system = root.find("e:System", _NS)
        if system is None:
            return None
        try:
            event_id = int((system.findtext("e:EventID", "", _NS) or "0").strip())
        except ValueError:
            event_id = 0
        time_text = system.findtext("e:TimeCreated", "", _NS)
        sys_time = (time_text.get("SystemTime") if time_text is not None else "") or ""
        provider_el = system.find("e:Provider", _NS)
        provider = (provider_el.get("Name") if provider_el is not None else "") or ""
        computer = system.findtext("e:Computer", "", _NS) or ""
        level_el = system.find("e:Level", _NS)
        level = (level_el.get("Name") if level_el is not None else "") or \
            system.findtext("e:Level", "", _NS)
        user_attr = system.find("e:Security", _NS)
        user = ""
        if user_attr is not None:
            user = user_attr.get("UserID", "") or ""
        keywords_el = system.find("e:Keywords", _NS)
        keywords = (keywords_el.get("Name") if keywords_el is not None else "") or ""
        correlation = ""
        rel = system.find("e:Correlation", _NS)
        if rel is not None:
            correlation = rel.get("ActivityID", "") or ""

        # rendered message (may be absent) + EventData summary
        message = ""
        rendering = root.find(".//e:RenderingInfo", _NS)
        if rendering is not None:
            message = (rendering.findtext("e:Message", "", _NS) or "").strip()
        data: Dict[str, str] = {}
        event_data = root.find("e:EventData", _NS)
        if event_data is not None:
            for d in event_data.findall("e:Data", _NS):
                name = d.get("Name") or ""
                value = (d.text or "").strip()
                if name:
                    data[name] = value
        if not message and data:
            summary = "; ".join(f"{k}={v}" for k, v in list(data.items())[:6])
            message = summary
        if not user:
            for field in _USER_FIELDS:
                if data.get(field):
                    user = data[field]
                    break
        dt = _parse_iso(sys_time)
        return {
            "time": dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else sys_time,
            "channel": channel,
            "event_id": event_id,
            "provider": provider,
            "computer": computer,
            "user": user,
            "level": level,
            "message": message,
            "keywords": keywords,
            "correlation_id": correlation,
            "_dt": dt,
        }


def _parse_iso(value: str) -> Optional[_dt.datetime]:
    if not value:
        return None
    try:
        dt = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        return dt
    except ValueError:
        return None
