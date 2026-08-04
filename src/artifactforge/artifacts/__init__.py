# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Single-format writers. One module per artifact format, each validated by a real parser.

Every writer here is a pure function of its arguments — no wall clock, no entropy, no
filesystem — so a scene composed from them regenerates byte-identical.

Depends on: model, content. Nothing here may import compose, bench or ingest.
"""
from artifactforge.artifacts.hive import (
    HiveTimestampSpec,
    build_amcache_hive,
    build_run_hive,
)
from artifactforge.artifacts.linux import build_bash_history, build_desktop_entry
from artifactforge.artifacts.macos import (
    build_knowledgec,
    build_launch_agent,
    build_quarantine_events,
    build_tcc,
    quarantine_xattr,
)
from artifactforge.artifacts.prefetch import (
    PrefetchTimestamps,
    build_prefetch,
    build_prefetch_v17_legacy,
    build_prefetch_v30,
    prefetch_name_hash,
    prefetch_vista_name_hash,
    prefetch_xp_name_hash,
)
from artifactforge.artifacts.shell_link import (
    ShellLinkTimestamps,
    ShellLinkValue,
    build_shell_link,
    parse_shell_link,
)
from artifactforge.artifacts.zone_identifier import (
    ZoneIdentifierValue,
    build_zone_identifier,
    parse_zone_identifier,
)
from artifactforge.artifacts.windows import ChromiumDownload, build_chromium_history
from artifactforge.artifacts.windows_task import (
    ScheduledTaskXmlValue,
    ScheduledTaskXmlWireValue,
    build_scheduled_task_xml,
    parse_scheduled_task_xml,
    read_scheduled_task_xml_wire,
    validate_scheduled_task_xml,
)

__all__ = [
    "HiveTimestampSpec", "build_run_hive", "build_amcache_hive",
    "PrefetchTimestamps", "build_prefetch", "build_prefetch_v17_legacy",
    "build_prefetch_v30", "prefetch_name_hash", "prefetch_vista_name_hash",
    "prefetch_xp_name_hash",
    "ShellLinkTimestamps", "ShellLinkValue", "build_shell_link", "parse_shell_link",
    "build_knowledgec", "build_tcc", "build_quarantine_events",
    "quarantine_xattr", "build_launch_agent",
    "build_bash_history", "build_desktop_entry",
    "ZoneIdentifierValue", "build_zone_identifier", "parse_zone_identifier",
    "ChromiumDownload", "build_chromium_history",
    "ScheduledTaskXmlValue", "ScheduledTaskXmlWireValue",
    "build_scheduled_task_xml", "parse_scheduled_task_xml",
    "read_scheduled_task_xml_wire", "validate_scheduled_task_xml",
]
