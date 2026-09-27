"""JOCKY forensic module registry.

Maps "module.entity" -> collector instance. Adding a new collector means
adding one class and registering it here — see manual §1.3 (extensibility
via plugin modules).
"""

from __future__ import annotations

from typing import Dict, List

from jocky.modules.base import CollectContext, Collector
from jocky.modules.sys.sysinfo import SysInfoCollector
from jocky.modules.mem.processes import ProcessesCollector
from jocky.modules.net.netinfo import (ConnectionsCollector, InterfacesCollector,
                                       ArpTableCollector, RoutingTableCollector,
                                       DnsCacheCollector)
from jocky.modules.reg.registry import (AutorunsCollector, ServicesCollector,
                                        MruCollector, UserAssistCollector)
from jocky.modules.log.events import WindowsEventsCollector
from jocky.modules.disk.files import FilesCollector


class ModuleRegistry:
    def __init__(self):
        self._collectors: Dict[str, Collector] = {}
        for cls in (SysInfoCollector, ProcessesCollector,
                    ConnectionsCollector, InterfacesCollector, ArpTableCollector,
                    RoutingTableCollector, DnsCacheCollector,
                    AutorunsCollector, ServicesCollector, MruCollector,
                    UserAssistCollector,
                    WindowsEventsCollector, FilesCollector):
            inst = cls()
            self._collectors[f"{inst.module}.{inst.entity}"] = inst

    # ------------------------------------------------------------------

    def get(self, key: str) -> Collector:
        return self._collectors[key]

    def exists(self, key: str) -> bool:
        return key in self._collectors

    def keys(self) -> List[str]:
        return sorted(self._collectors.keys())

    def modules(self) -> List[str]:
        return sorted({c.module for c in self._collectors.values()})

    def run(self, key: str, args, kwargs, ctx: CollectContext) -> List[dict]:
        collector = self._collectors[key]
        return collector.collect(args, kwargs, ctx)

    def catalog(self) -> List[dict]:
        """Description of every collector (used by the UI + doctor)."""
        out = []
        for key in self.keys():
            c = self._collectors[key]
            out.append({
                "key": key,
                "title": c.title,
                "record_type": c.record_type,
                "fields": c.fields,
                "columns": c.columns,
            })
        return out
