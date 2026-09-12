"""A build host whose request and services require no window.

prepare_build supplies repositories, runtime credentials and a validated plan.
The same host can execute an explicitly prepared plan. Events remain available
for consumers, and the runner also returns a structured terminal outcome.
"""
from __future__ import annotations

import copy
from typing import Optional

from build_spec import BuildSpec
from feathered_app.build_backend import BuildBackendMixin
from feathered_app.build_intent import BuildIntentMixin
from feathered_app.build_mirror import BuildMirrorMixin
from feathered_app.build_output import BuildOutputMixin
from feathered_app.build_plan import BuildPlanMixin
from feathered_app.build_request import BuildRequestMixin
from feathered_app.build_preparation import BuildPreparationMixin
from feathered_app.build_output import confirm_publication
from feathered_app.build_services import BuildServices
from feathered_app.build_service_host import BuildServiceHost, _BuildCancelEvent
from feathered_app.build_sources import BuildSourcesMixin
from feathered_app.repository_universe import RepositoryUniverseMixin


class HeadlessHost(BuildServiceHost, BuildRequestMixin, BuildIntentMixin, BuildBackendMixin,
                   BuildPlanMixin, BuildSourcesMixin, BuildOutputMixin,
                   BuildMirrorMixin, BuildPreparationMixin, RepositoryUniverseMixin):
    """Everything `build_runner.run` reaches for, without a widget behind it."""

    def __init__(self, spec: BuildSpec, services: BuildServices,
                 repositories=(), selected_packages=(), *, workloads=None):
        self._build_snapshot = spec
        BuildServiceHost.__init__(self, services)
        #  The five pieces of state a host holds rather than derives.
        self.repo_rows = list(repositories)
        self.selected_packages = list(selected_packages)
        self.ignored_unresolved: set = set()
        self.vendor_signature_profiles = {}
        self.resolution_pass_budget = 0
        self.loaded_signature = None
        self.loaded_packages = []
        #  Frozen naming instant, the same guarantee start_build gives: the name
        #  computed at confirmation and at write time must be identical.
        from datetime import datetime
        self._build_naming_time = datetime.now()
        #  The workload catalogue, loaded rather than inherited from a wizard
        #  that populated it during UI construction.
        from workloads import load_workloads
        self.workloads = copy.deepcopy(dict(workloads)) if workloads is not None else load_workloads()
        self.last_warnings: list = []
        self.last_output_path: Optional[str] = None

    def _confirm_output_folder_name(self, folder_name, options=None):
        return confirm_publication(self, folder_name, options,
                                   choose=self._services.publication_policy)

