"""Shared imports and UI constants for Feathered 1.2.

This module intentionally contains no application state or workflow logic.
"""

from __future__ import annotations

import copy
import json
import math
import os
import queue
import subprocess
import sys
import urllib.parse
import re
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional
import tkinter as tk
from tkinter import filedialog, messagebox as _native_messagebox, simpledialog, ttk

from core import (
    ResolutionResult,
    redact_url, redact_text,
    compare_evr,
    path_to_file_url,
    BuildOptions, Cancelled, RepoSpec, Reporter,
    compare_evr as rpm_compare_evr, fetch_text, format_requirement as rpm_format_requirement,
    gpg_backend, gpg_backend_version, load_repository as rpm_load_repository, package_versions as rpm_package_versions,
    parse_target_inventory as rpm_parse_target_inventory, probe_repository as rpm_probe_repository,
    resolve as rpm_resolve, write_bundle as rpm_write_bundle, write_bundle_archive as rpm_write_bundle_archive,
    zstd_backend, FEATHERED_VERSION, package_digest_map, mirrors_are_distinct,
    repository_verification_strategy, infer_vendor_id, vendor_display_name,
    evidence_repo_for_url, evidence_artifact_candidates, evidence_relationship,
    evidence_authority_relationship,
    find_independent_peer_package, independent_peer_packages_match,
    repo_relative_url, spot_compare_artifact_urls, spot_compare_peer_artifact_urls,
)
import apt_core
import arch_core
import repository_tools
import mirror_catalog
from profiles import (PROFILES, discover_apt_releases, extract_versions, profile_by_label,
                      version_key)
from evidence_model import (
    EvidenceCandidate, REL_EXACT_MIRROR, REL_EXACT_ARTIFACT, REL_REBUILD_PEER,
    AUTH_INDEPENDENT, AUTH_UNKNOWN, candidate_display_label, repository_channel,
    repositories_are_exact_mirror_compatible,
)
from feathered_app.status_text import FOOTER_STATUS_LINES, condense_status_text
from mirror_unification import (MERGE_POLICY_LABELS, MergePolicy, conflict_report,
                                 merge_policy_from_label, mirror_sources_record,
                                 unified_mirror_note, unify_mirror_packages)
from source_model import RootSourcePolicy, SourcePlan
from acquisition_model import (
    MIRROR_LAYOUT_LABELS, WORKLOAD_PACKAGE_ONLY_MODE,
    AcquisitionIntent, AcquisitionCapability, AcquisitionState, AnalysisType, MirrorLayout,
    PublicationType, VerificationScope, derive_acquisition_state, intent_from_selection_mode,
    mirror_layout_from_label,
)
from source_readiness import (evaluate_source_readiness, missing_reachable_scopes,
                              repository_purpose)
import workload_resolution
from workloads import load_workloads, workload_by_label
from workload_materialization import materialize_source_plan, MaterializedWorkload

APP_TITLE = "Feathered"
APP_SUBTITLE = "Airgap Sideloading"
APP_VERSION = FEATHERED_VERSION  # keep GUI/provenance version in lockstep.

# Feathered runs dark. One ramp for depth, one accent for meaning.
BG_APP = "#11151C"
BG_RAIL = "#161B24"
BG_RAIL_ACTIVE = "#1F2733"
BG_PANEL = "#1A202A"
BG_INPUT = "#232B37"
BG_HEADER = "#0D1117"
LINE = "#2C3542"

FG_TEXT = "#E6EAF0"
FG_MUTED = "#8A97A8"
FG_DIM = "#5F6B7A"
BG_DISABLED = "#171C24"
LINE_DISABLED = "#242C37"

ACCENT = "#4FB58B"
ACCENT_DIM = "#2E6E55"
ACCENT_TEXT = "#0D1117"
INK_FAINT = "#3A4551"   # barely-there chevron trail

OK_FG = "#5CC98C"
WARN_FG = "#E0A458"
ERR_FG = "#E4736B"

ASSURANCE_COLORS = {
    "vendor-signature": OK_FG,
    "archive-chain": ACCENT,
    "corroborated-digest": OK_FG,  # two metadata sources, one verified payload.
    "independent-digest": OK_FG,
    "metadata-corroborated": WARN_FG,
    "digest-only": WARN_FG,
    "unverified": ERR_FG,
}

from feathered_app.build_output import FOLDER_SCHEMES  # noqa: F401

MODES = ["Complete bundle (recommended)", "Target-aware complete",
         "Complete + weak dependencies"]
WORKLOAD_MODES = [*MODES, WORKLOAD_PACKAGE_ONLY_MODE]
