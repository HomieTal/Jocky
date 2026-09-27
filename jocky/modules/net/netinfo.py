"""net module: network forensics (read-only, manual §10).

Implements the manual's `connection` forensic type (§5.3): local_addr,
local_port, remote_addr, remote_port, protocol, state, pid, process_name.
Plus interfaces, ARP table, routing table and DNS cache snapshots.
No packet capture / covert networking in the prototype.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from jocky.modules.base import CollectContext, Collector
from jocky.modules import winutil

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def _pid_name(pid) -> str:
    if not psutil or not pid:
        return ""
    try:
        return psutil.Process(pid).name()
    except Exception:
        return ""


class ConnectionsCollector(Collector):
    module = "net"
    entity = "connections"
    title = "Network Connections"
    record_type = "connection"
    fields = ["local_addr", "local_port", "remote_addr", "remote_port",
              "protocol", "state", "pid", "process_name"]
    columns = ["process_name", "pid", "protocol", "local_addr", "local_port",
               "remote_addr", "remote_port", "state"]
    arg_spec = {"kind": {"type": "str", "default": "inet"}}

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        if psutil is None:
            from jocky.runtime import errors
            raise errors.collect_failed("psutil is not available on this host")
        opts = self.resolve_args(args, kwargs)
        kind = {"inet": "inet", "inet4": "inet4", "inet6": "inet6",
                "tcp": "tcp", "udp": "udp"}.get(str(opts["kind"]), "inet")
        ctx.progress("enumerating network connections...")
        conns = psutil.net_connections(kind=kind)
        records: List[Dict[str, Any]] = []
        name_cache: Dict[int, str] = {}
        import socket as _socket
        for c in conns:
            proto = "UDP" if c.type == _socket.SOCK_DGRAM else "TCP"
            laddr = getattr(c, "laddr", None)
            raddr = getattr(c, "raddr", None)
            pid = c.pid or 0
            if pid and pid not in name_cache:
                name_cache[pid] = _pid_name(pid)
            records.append({
                "local_addr": laddr.ip if laddr else "",
                "local_port": laddr.port if laddr else None,
                "remote_addr": raddr.ip if raddr else "",
                "remote_port": raddr.port if raddr else None,
                "protocol": proto,
                "state": c.status if proto == "TCP" else "",
                "pid": pid or None,
                "process_name": name_cache.get(pid, ""),
            })
        records.sort(key=lambda r: (r["protocol"], r["state"], r["local_port"] or 0))
        return records


class InterfacesCollector(Collector):
    module = "net"
    entity = "interfaces"
    title = "Network Interfaces"
    record_type = "interface"
    fields = ["name", "up", "speed_mbps", "mtu", "mac", "ipv4", "ipv6"]
    columns = ["name", "up", "speed_mbps", "mac", "ipv4", "ipv6", "mtu"]

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        if psutil is None:
            from jocky.runtime import errors
            raise errors.collect_failed("psutil is not available on this host")
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        records = []
        for name, addr_list in addrs.items():
            ipv4 = ";".join(a.address for a in addr_list
                            if getattr(a, "family", None) == 2)  # AF_INET
            ipv6 = ";".join(a.address for a in addr_list
                            if getattr(a, "family", None) == 23)  # AF_INET6 (Win)
            mac = next((a.address for a in addr_list
                        if getattr(a, "family", None) == psutil.AF_LINK), "")
            st = stats.get(name)
            records.append({
                "name": name,
                "up": bool(st.isup) if st else None,
                "speed_mbps": st.speed if st else None,
                "mtu": st.mtu if st else None,
                "mac": mac,
                "ipv4": ipv4,
                "ipv6": ipv6,
            })
        return records


class ArpTableCollector(Collector):
    module = "net"
    entity = "arp_table"
    title = "ARP Table"
    record_type = "entry"
    fields = ["interface", "ip", "mac", "type"]
    columns = ["interface", "ip", "mac", "type"]

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        rc, out = winutil.run_capture(["arp", "-a"], timeout=20)
        if rc != 0:
            from jocky.runtime import errors
            raise errors.collect_failed(f"'arp -a' failed (exit {rc})")
        records: List[Dict[str, Any]] = []
        iface = ""
        for line in out.splitlines():
            line = line.strip()
            m = re.match(r"Interface:\s*(\S+)", line)
            if m:
                iface = m.group(1)
                continue
            m = re.match(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
            if m:
                records.append({
                    "interface": iface,
                    "ip": m.group(1),
                    "mac": m.group(2),
                    "type": m.group(3),
                })
        return records


class RoutingTableCollector(Collector):
    module = "net"
    entity = "routing_table"
    title = "IPv4 Routing Table"
    record_type = "entry"
    fields = ["destination", "netmask", "gateway", "interface", "metric"]
    columns = ["destination", "netmask", "gateway", "interface", "metric"]

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        rc, out = winutil.run_capture(["route", "print", "-4"], timeout=20)
        if rc != 0:
            from jocky.runtime import errors
            raise errors.collect_failed(f"'route print -4' failed (exit {rc})")
        records: List[Dict[str, Any]] = []
        in_active = False
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Active Routes"):
                in_active = True
                continue
            if in_active:
                if line.startswith("="):
                    break
                m = re.match(
                    r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})"
                    r"\s+(\d{1,3}(?:\.\d{1,3}){3}|\*)\s+(\S+)\s+(\d+)", line)
                if m:
                    records.append({
                        "destination": m.group(1),
                        "netmask": m.group(2),
                        "gateway": m.group(3),
                        "interface": m.group(4),
                        "metric": int(m.group(5)),
                    })
        return records


class DnsCacheCollector(Collector):
    module = "net"
    entity = "dns_cache"
    title = "DNS Resolver Cache"
    record_type = "entry"
    fields = ["name", "record_type", "ttl", "data", "section"]
    columns = ["name", "record_type", "ttl", "data", "section"]

    def collect(self, args, kwargs, ctx: CollectContext) -> List[Dict[str, Any]]:
        rc, out = winutil.run_capture(["ipconfig", "/displaydns"], timeout=30)
        if rc != 0:
            from jocky.runtime import errors
            raise errors.collect_failed(
                f"'ipconfig /displaydns' failed (exit {rc}); the DNS Client "
                "service may be disabled")
        records: List[Dict[str, Any]] = []
        current: Dict[str, Any] = {}
        field_re = re.compile(r"^(.*?)\s*\.{2,}\s*(.*)\s*:\s*(.*)$")
        kv_re = re.compile(r"^\s*(.+?)\s*\.{2,}\s*:\s*(.*)$")
        for raw in out.splitlines():
            line = raw.rstrip()
            if not line.strip():
                if current.get("name"):
                    records.append(current)
                current = {}
                continue
            if line.strip().startswith("Record Name"):
                if current.get("name"):
                    records.append(current)
                current = {"name": line.split(":", 1)[1].strip() if ":" in line else "",
                           "record_type": "", "ttl": None, "data": "", "section": ""}
                continue
            m = kv_re.match(line)
            if m and current:
                key = m.group(1).strip().lower()
                val = m.group(2).strip()
                if "record type" in key:
                    current["record_type"] = val
                elif "time to live" in key:
                    digits = re.sub(r"\D", "", val.split("(")[0])
                    current["ttl"] = int(digits) if digits else None
                elif "section" in key:
                    current["section"] = val
                elif "record" in key or "ptr" in key or "host" in key or "cname" in key:
                    if not current["data"]:
                        current["data"] = val
        if current.get("name"):
            records.append(current)
        return records
