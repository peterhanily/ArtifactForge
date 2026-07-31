"""ArtifactForge — deterministic forensic-artifact companion to EvidenceForge."""
from artifactforge.contentstore import Content, ContentStore, build_pe_stub, imphash_of
from artifactforge.ef_seeds import content_id, sysmon_seed, sysmon_sha256
from artifactforge.hive import build_amcache_hive, build_run_hive
from artifactforge.prefetch import build_prefetch
from artifactforge.benchmark import Question, Score, Task, generate_batch, grade
from artifactforge.profile import HostProfile, deterministic_uuid, macos_profile, windows_profile
from artifactforge.scenario import CrimeScene, build_crime_scene, build_macos_crime_scene

__all__ = ["Content", "ContentStore", "build_pe_stub", "imphash_of",
           "content_id", "sysmon_seed", "sysmon_sha256",
           "build_run_hive", "build_amcache_hive", "build_prefetch",
           "HostProfile", "windows_profile", "macos_profile", "deterministic_uuid",
           "CrimeScene", "build_crime_scene", "build_macos_crime_scene",
           "Task", "Question", "Score", "generate_batch", "grade"]
__version__ = "0.0.1"
