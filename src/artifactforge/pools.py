# Copyright (c) 2026 Peter Hanily
# SPDX-License-Identifier: MIT
"""Variation pools — the vocabulary scenarios are drawn from.

Sized so that guessing is not a strategy. The previous pools held four to six entries each
and were indexed by `i % len(pool)` from a batch counter that stepped by two, so only half of
each even-length pool was ever reachable and host was locked to user: three distinct
(host, user) pairs at any batch size. Selection is now keyed per scenario and per field.

Every name here is invented. Domains are RFC 2606 reserved, which Gate 3 enforces on the
emitted bytes rather than trusting this file.
"""

USERS = (
    "v", "jdoe", "asmith", "mchen", "kpatel", "rgarcia", "tnguyen", "lokafor",
    "bmurphy", "swhite", "dkowalski", "hyamamoto", "fbernard", "ncosta", "pivanov",
    "gschmidt", "aoyelaran", "mrossi", "ekallio", "csantos", "wzhang", "jdupont",
    "ahaddad", "obrien", "tsvensson", "rkumar", "mdlamini", "lfontaine", "pnovak",
    "kjensen", "sabbasi", "vtakahashi",
)

HOSTS = (
    "WKSTN", "POS", "FIN", "HR", "DEV", "OPS", "LEGAL", "SALES", "MKTG", "ENG",
    "LAB", "QA", "BUILD", "DESK", "TERM", "KIOSK", "CAD", "MED", "EDU", "WARE",
    "DISP", "FLEET", "PROC", "AUDIT", "RISK", "TREAS", "SUPP", "FIELD", "REMOTE",
    "BRANCH", "STORE", "DEPOT",
)

# Names that look like something a user would not question. All fabricated.
MALWARE_NAMES = (
    "update.exe", "svc_host.exe", "adobe_up.exe", "chrome_helper.exe", "win_defend.exe",
    "printsvc.exe", "onedrv_sync.exe", "teams_upd.exe", "java_check.exe", "vpn_agent.exe",
    "audiodrv.exe", "nettrace.exe", "sysmon64.exe", "backupsvc.exe", "licensing.exe",
    "gpupd_helper.exe", "spoolsvr.exe", "certmgr_svc.exe", "wmi_perf.exe", "dnscache.exe",
    "taskeng_x.exe", "msiexec_up.exe", "srvhost32.exe", "ctfmon_x64.exe", "smartscrn.exe",
    "winlogon_h.exe", "lsass_mon.exe", "shellexp.exe", "rundll_svc.exe", "conhost_x.exe",
    "dllhost_up.exe", "explorer_h.exe",
)

# Plausible, entirely ordinary programs — the noise a real host is full of.
BENIGN_NAMES = (
    "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe", "powershell.exe", "explorer.exe",
    "winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "firefox.exe", "code.exe",
    "putty.exe", "7zFM.exe", "vlc.exe", "acrord32.exe", "slack.exe", "zoom.exe",
    "teams.exe", "onedrive.exe", "dropbox.exe", "git-bash.exe", "python.exe", "node.exe",
    "javaw.exe", "steam.exe", "spotify.exe", "gimp.exe", "audacity.exe", "filezilla.exe",
    "winscp.exe", "thunderbird.exe",
)

RUN_VALUE_NAMES = (
    "Updater", "OneDriveSetup", "SecurityHealth", "AdobeARM", "SunJavaUpdateSched",
    "TeamsMachineInstaller", "Dropbox", "Greenshot", "RTHDVCPL", "IgfxTray",
    "SynTPEnh", "CCleanerMonitoring", "Steam", "Discord", "Spotify", "BackupAssist",
    "PrinterAgent", "VPNClient", "LicenseCheck", "NetTraceHelper", "AudioDriverSvc",
    "CertRenewal", "WmiPerfMon", "DnsCacheSvc", "TaskEngineX", "MsiUpdater",
    "ServerHost32", "InputMethodX", "SmartScreenX", "ShellExpHelper", "DllHostUp",
    "ExplorerHelper",
)

BUNDLES = (
    "com.acme.updater", "io.opncast.helper", "net.zeta.sync", "org.freeware.tool",
    "com.northwind.agent", "io.lumenpad.daemon", "net.quillbox.relay", "org.tessellate.svc",
    "com.harborline.sync", "io.driftwood.helper", "net.cinderblock.node", "org.pelagic.tool",
    "com.silverbirch.updater", "io.mossgate.agent", "net.arclight.relay", "org.foldmark.svc",
    "com.riverstone.helper", "io.brackenfell.sync", "net.tinderbox.node", "org.wavecrest.tool",
    "com.copperfield.agent", "io.stonewell.daemon", "net.glasswing.relay", "org.marrowbone.svc",
    "com.thornfield.sync", "io.hollowpine.helper", "net.saltmarsh.node", "org.embergrove.tool",
    "com.windrow.updater", "io.slatebeck.agent", "net.foxglove.relay", "org.ashcombe.svc",
)

BENIGN_BUNDLES = (
    "com.apple.Safari", "com.apple.mail", "com.apple.Notes", "com.apple.Terminal",
    "com.microsoft.VSCode", "com.google.Chrome", "org.mozilla.firefox", "com.tinyspeck.slackmacgap",
    "us.zoom.xos", "com.spotify.client", "com.figma.Desktop", "com.postmanlabs.mac",
    "com.docker.docker", "com.apple.Preview", "com.apple.iCal", "com.apple.systempreferences",
)

# RFC 2606 reserved. Gate 3 checks the emitted bytes, not this list.
DOWNLOAD_HOSTS = (
    "cdn.evil.example", "files.badactor.example", "dl.malicious.test", "assets.rogue.invalid",
    "static.threat.example", "pkg.untrusted.test", "mirror.hostile.invalid", "get.sketchy.example",
)

DOWNLOAD_AGENTS = ("Safari", "Google Chrome", "Firefox", "curl", "Brave Browser")

TCC_SERVICES = (
    "kTCCServiceSystemPolicyAllFiles", "kTCCServiceAccessibility", "kTCCServiceScreenCapture",
    "kTCCServiceMicrophone", "kTCCServiceCamera", "kTCCServiceAppleEvents",
)
