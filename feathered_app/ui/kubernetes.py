"""Small workload-specific adapters for existing Content/Repository/Review stages."""
from copy import deepcopy
from dataclasses import replace
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import apt_core
import core
from feathered_app.context import tk, ttk
from feathered_app.build_request import BuildRequestMixin
from kubernetes_workflow import KUBERNETES_KEYS, VKS_KEY, rolling_source, report
from k8s_version import parse
import k8s_discovery
import k8s_knowledge


class KubernetesWorkloadMixin:
    def _query_jobs(self):
        # Preserve use of this mixin by existing non-window adapters as well.
        from feathered_app.application.operations import OperationsMixin
        return OperationsMixin._query_jobs(self)

    def _build_kubernetes_content_controls(self, parent):
        self.k8s_minor_var = tk.StringVar(value='')
        self.apiserver_oldest_minor_var = tk.StringVar(value='')
        self.apiserver_newest_minor_var = tk.StringVar(value='')
        self.pin_to_inventory_baseline_var = tk.BooleanVar(value=True)
        self.advisories_acknowledged_var = tk.BooleanVar(value=False)
        self.image_baker_name_var = tk.StringVar(value='feathered-node-additions')
        self.k8s_observation_var = tk.StringVar(value='')
        self.k8s_knowledge_var = tk.StringVar(value='')
        # Repository minor and full package build are independent selections.
        for widget in parent.winfo_children():
            info = widget.grid_info()
            if info and int(info['row']) >= 2:
                row = int(info['row'])
                widget.grid_configure(row=row + (3 if row >= 4 else 2))
        self.k8s_minor_controls = ttk.Frame(parent, style='Panel.TFrame')
        self.k8s_minor_controls.grid(row=2, column=0, columnspan=3, sticky='ew', pady=(12, 0))
        self.k8s_minor_controls.columnconfigure(0, weight=1)
        ttk.Label(self.k8s_minor_controls, text='Kubernetes minor repository', style='Panel.TLabel').grid(row=0, column=0, sticky='w')
        self.k8s_minor_combo = ttk.Combobox(self.k8s_minor_controls, textvariable=self.k8s_minor_var, state='normal')
        self.k8s_minor_combo.grid(row=1, column=0, sticky='ew')
        refresh = ttk.Button(self.k8s_minor_controls, text='Refresh minors', command=lambda: self._discover_kubernetes_minors(force=True))
        refresh.grid(row=1, column=1, padx=(10, 0))
        self._register_operation_control(refresh)
        self._register_operation_control(self.k8s_minor_combo)
        self.k8s_patch_status_var = tk.StringVar(value='')
        self.k8s_patch_status = ttk.Label(parent, textvariable=self.k8s_patch_status_var, style='PanelHint.TLabel', wraplength=680)
        self.k8s_patch_status.grid(row=6, column=0, columnspan=3, sticky='ew', pady=(4, 0))
        self.k8s_observation_label = ttk.Label(parent, textvariable=self.k8s_observation_var, style='PanelHint.TLabel', wraplength=680)
        self.k8s_observation_label.grid(row=3, column=0, columnspan=3, sticky='ew', pady=(4, 0))
        self.vks_options = ttk.Frame(parent, style='Panel.TFrame')
        self.vks_options.grid(row=14, column=0, columnspan=3, sticky='ew', pady=(8, 0))
        check = self._image_checkbutton(self.vks_options, self.pin_to_inventory_baseline_var,
                                        'Pin to inventory baseline',
                                        command=self._apply_vks_baseline_sources)
        self._register_operation_control(check)
        ttk.Label(self.vks_options, text='Image Baker draft name', style='Panel.TLabel').pack(anchor='w')
        entry = ttk.Entry(self.vks_options, textvariable=self.image_baker_name_var)
        entry.pack(fill='x'); self._register_operation_control(entry)
        ttk.Label(self.vks_options, text='Choose additions in the package chooser on Repositories. Load a captured node inventory on Target.',
                  style='PanelHint.TLabel', wraplength=660).pack(anchor='w')
        self.vks_options.grid_remove()
        self.k8s_minor_var.trace_add('write', self._k8s_minor_changed)
        for var in (self.apiserver_oldest_minor_var, self.apiserver_newest_minor_var):
            var.trace_add('write', self._k8s_advice_changed)

    def _build_kubernetes_repository_controls(self, parent):
        self.k8s_api_card = self._card(parent, 'Cluster API server minor (optional)', pady=(12, 0))
        row = ttk.Frame(self.k8s_api_card, style='Panel.TFrame'); row.pack(fill='x')
        for col, (label, variable) in enumerate((('Oldest', self.apiserver_oldest_minor_var), ('Newest', self.apiserver_newest_minor_var))):
            ttk.Label(row, text=label, style='Panel.TLabel').grid(row=0, column=col, sticky='w')
            entry = ttk.Entry(row, textvariable=variable, width=16)
            entry.grid(row=1, column=col, sticky='w', padx=(0, 12)); self._register_operation_control(entry)
        self._panel_hint(self.k8s_api_card, 'Enter the Kubernetes minors running on your API servers, such as 1.33. Leave blank to use the selected repository minor as an assumption.')
        ttk.Label(self.k8s_api_card, textvariable=self.k8s_knowledge_var, style='PanelHint.TLabel', wraplength=680).pack(fill='x', pady=(8, 0))
        self._set_card_visible(self.k8s_api_card, False)

    def _sync_kubernetes_controls(self, discover=True):
        if 'k8s_minor_var' not in self.__dict__:
            return
        key = self._workload().key
        active = key in KUBERNETES_KEYS
        if not active and '_background_query_jobs' in self.__dict__:
            self._background_query_jobs.cancel('k8s-patches')
        self.package_version_label.configure(text='Package patch / build' if active else 'Version')
        self.k8s_minor_controls.grid() if active else self.k8s_minor_controls.grid_remove()
        self.k8s_patch_status.grid() if active else self.k8s_patch_status.grid_remove()
        self.vks_options.grid() if key == VKS_KEY else self.vks_options.grid_remove()
        self.k8s_observation_label.grid() if active else self.k8s_observation_label.grid_remove()
        card = self.__dict__.get('k8s_api_card')
        if card is not None:
            self._set_card_visible(card, active)
        if active:
            family = self._profile().package_family
            if '_k8s_knowledge' not in self.__dict__:
                self._k8s_knowledge = k8s_knowledge.read(self._release_cache_path().with_name('kubernetes-knowledge.json')) or k8s_knowledge.bundled()
            observation = self.__dict__.setdefault('_k8s_observations', {}).get(family)
            if observation is None:
                observation = k8s_discovery.read(self._release_cache_path().with_name('kubernetes-' + family + '.json'))
                if observation is not None:
                    self._k8s_observations[family] = observation
            choices = observation.versions if observation else self._k8s_knowledge.repository_candidates
            self.k8s_minor_combo['values'] = choices
            self.k8s_minor_combo.configure(state='normal')
            self.k8s_observation_var.set(('Observed ' + observation.observed_at + ' from ' + observation.source + '. ' + observation.error)
                if observation else 'Published minors from bundled/cached upstream data; repository availability is being checked. You can type a minor.')
            if choices and not self.k8s_minor_var.get():
                self.k8s_minor_var.set(choices[0])
            self._update_k8s_knowledge_note()
            if discover and family not in self.__dict__.setdefault('_k8s_observed_session', set()):
                self._discover_kubernetes_minors()
            if discover and self.k8s_minor_var.get():
                self._queue_k8s_patch_scan()
        self._apply_vks_baseline_sources()

    def _discover_kubernetes_minors(self, force=False):
        family = self._profile().package_family
        running = self.__dict__.setdefault('_k8s_discovery_running', set())
        if family in running:
            return
        running.add(family)
        self.k8s_observation_var.set('Checking available minor repositories… You can select or type a minor while this runs.')
        self.__dict__.setdefault('_k8s_knowledge_waiters', set()).add(family)
        if self.__dict__.get('_k8s_knowledge_refresh_running'):
            return
        self._k8s_knowledge_refresh_running = True
        generation = self.__dict__.get('_k8s_knowledge_generation', 0) + 1
        self._k8s_knowledge_generation = generation
        path = self._release_cache_path().with_name('kubernetes-knowledge.json')
        previous = self.__dict__.get('_k8s_knowledge') or k8s_knowledge.read(path) or k8s_knowledge.bundled()
        def work(cancel):
            try:
                knowledge = k8s_knowledge.refresh(path, previous, force=force)
            except Exception as exc:
                knowledge = replace(previous, error=core.redact_text(str(exc)))
            return ('k8s_knowledge_finished', generation, knowledge)
        self._query_jobs().submit('k8s-knowledge', work)

    def _finish_k8s_knowledge_refresh(self, generation, knowledge):
        if (generation != self.__dict__.get('_k8s_knowledge_generation')
                or not self.__dict__.get('_k8s_knowledge_refresh_running')):
            return
        self._k8s_knowledge_refresh_running = False
        families = self.__dict__.pop('_k8s_knowledge_waiters', set())
        try:
            self._receive_k8s_knowledge(knowledge)
        finally:
            for family in families:
                self._start_k8s_repository_discovery(family, knowledge)

    def _start_k8s_repository_discovery(self, family, knowledge):
        events = self.events
        def probe(url):
            return k8s_discovery.probe_repository(url, opener=urlopen)
        def work(cancel):
            try:
                observation = k8s_discovery.discover(family,
                    lambda url: k8s_discovery.ProbeResult('indeterminate', 'Cancelled') if cancel.is_set() else probe(url),
                    lambda observation: events.put(('k8s_observation_progress', family, observation)),
                    candidates=knowledge.repository_candidates or None)
            except Exception as exc:
                observation = k8s_discovery.Observation((), '', 'https://pkgs.k8s.io', core.redact_text(str(exc)))
            return ('k8s_observation', family, observation)
        self._query_jobs().submit('k8s-repositories-' + family, work)

    def _query_failed(self, operation, error):
        """Release UI ownership even if a query could not start its worker."""
        self._log('Background query failed: ' + error)
        if operation == 'k8s-knowledge':
            previous = self.__dict__.get('_k8s_knowledge') or k8s_knowledge.bundled()
            self._finish_k8s_knowledge_refresh(self._k8s_knowledge_generation, replace(previous, error=error))
        elif operation.startswith('k8s-repositories-'):
            family = operation.removeprefix('k8s-repositories-')
            self._receive_k8s_observation(family, k8s_discovery.Observation((), '', 'https://pkgs.k8s.io', error))
        elif operation == 'k8s-patches':
            self.k8s_patch_status_var.set('Could not load versions: ' + error + '. Use Refresh versions to retry.')

    def _receive_k8s_observation(self, family, observation, complete=True):
        if self._busy():
            self.after(500, lambda: self._receive_k8s_observation(family, observation, complete)); return
        if not complete:
            if self._profile().package_family == family and self._workload().key in KUBERNETES_KEYS:
                self.k8s_minor_combo['values'] = tuple(sorted(set(self.k8s_minor_combo['values']) | set(observation.versions), key=lambda v: parse(v).minor, reverse=True))
                self.k8s_observation_var.set(f'Found {len(observation.versions)} minor repositories; checking for more… Select one now or enter a minor.')
            return
        self.__dict__.setdefault('_k8s_discovery_running', set()).discard(family)
        self.__dict__.setdefault('_k8s_observed_session', set()).add(family)
        previous = self.__dict__.setdefault('_k8s_observations', {}).get(family)
        observation = k8s_discovery.retain(previous, observation)
        self.__dict__.setdefault('_k8s_observations', {})[family] = observation
        try:
            k8s_discovery.save(self._release_cache_path().with_name('kubernetes-' + family + '.json'), observation)
        except OSError as exc:
            self._log('Could not cache Kubernetes observation: ' + str(exc))
        if self._profile().package_family == family:
            self._sync_kubernetes_controls(discover=False)
            self._schedule_k8s_refresh(bool(observation.error or getattr(self.__dict__.get('_k8s_knowledge'), 'error', '')))

    def _receive_k8s_knowledge(self, knowledge):
        if self._busy():
            self.after(500, lambda: self._receive_k8s_knowledge(knowledge)); return
        self._k8s_knowledge = k8s_knowledge.reconcile(self.__dict__.get('_k8s_knowledge'), knowledge)
        self._update_k8s_knowledge_note()
        self._render_kubernetes_advice()

    def _update_k8s_knowledge_note(self):
        knowledge = self.__dict__.get('_k8s_knowledge')
        if knowledge is None or 'k8s_knowledge_var' not in self.__dict__:
            return
        try:
            messages = k8s_knowledge.notices(knowledge, (self.k8s_minor_var.get(), self.apiserver_oldest_minor_var.get(), self.apiserver_newest_minor_var.get()))
        except ValueError:
            messages = ['Enter a Kubernetes minor such as 1.33 or 33.']
        self.k8s_knowledge_var.set(k8s_knowledge.summary(knowledge) + '\n' + '\n'.join(messages))

    def _schedule_k8s_refresh(self, failed):
        pending = self.__dict__.pop('_k8s_refresh_after', None)
        if pending:
            self.after_cancel(pending)
        failures = min(self.__dict__.get('_k8s_refresh_failures', 0) + 1, 3) if failed else 0
        self._k8s_refresh_failures = failures
        seconds = (60, 300, 900)[failures - 1] if failures else k8s_knowledge.TTL_SECONDS
        self._k8s_refresh_after = self.after(seconds * 1000, self._retry_k8s_refresh)

    def _retry_k8s_refresh(self):
        self.__dict__.pop('_k8s_refresh_after', None)
        if self._workload().key not in KUBERNETES_KEYS or self._busy():
            self._k8s_refresh_after = self.after(60000, self._retry_k8s_refresh); return
        self._discover_kubernetes_minors(force=True)

    def _k8s_minor_changed(self, *_args):
        if self.__dict__.get('_restoring_workload_controls') or self._workload().key not in KUBERNETES_KEYS:
            return
        self.advisories_acknowledged_var.set(False)
        self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
        self.single_catalog_signature = None; self.single_catalog_packages = []
        self.package_version_var.set('Latest')
        self.package_version_combo['values'] = ('Latest',)
        try:
            parse(self.k8s_minor_var.get())
            self._activate_workload_repository_selection()
            self._queue_k8s_patch_scan()
        except ValueError as exc:
            self.k8s_observation_var.set(str(exc))
        self._update_k8s_knowledge_note()

    def _queue_k8s_patch_scan(self):
        if '_background_query_jobs' in self.__dict__:
            self._background_query_jobs.cancel('k8s-patches')
        pending = self.__dict__.pop('_k8s_patch_after', None)
        if pending:
            self.after_cancel(pending)
        self.k8s_patch_status_var.set('Loading available patch/build versions…')
        self._k8s_patch_after = self.after(200, self._scan_k8s_patch_versions)

    def _k8s_patch_context(self):
        if self._workload().key not in KUBERNETES_KEYS:
            return None
        return (self._profile().key, self._profile().package_family, self.release_var.get(),
                self.arch_var.get(), self._workload().key, self.k8s_minor_var.get(),
                tuple((r.source_identity, r.url, r.enabled) for r in self.repo_rows if r.role == 'kubernetes'))

    def _scan_k8s_patch_versions(self, refresh=False):
        self.__dict__.pop('_k8s_patch_after', None)
        context = self._k8s_patch_context()
        if context is None:
            return
        try:
            parse(self.k8s_minor_var.get())
            repos, role = self._version_scan_repositories(self._workload())
        except (ValueError, RuntimeError) as exc:
            self.k8s_patch_status_var.set(str(exc)); return
        cached = self.__dict__.setdefault('_k8s_patch_cache', {}).get(context)
        if cached is not None and not refresh:
            self._receive_k8s_patch_versions(context, cached, ''); return
        self.k8s_patch_status_var.set('Loading available patch/build versions… You can keep using the other controls.')
        backend = apt_core if self._profile().package_family == 'deb' else core
        arch = self.arch_var.get()
        names = tuple(self._workload().versioned_packages)
        repos = deepcopy(repos)
        def work(cancel):
            try:
                packages = []
                for repo in repos:
                    packages.extend(backend.load_repository(repo, {arch, 'noarch', 'all'}, core.Reporter(cancel_event=cancel)))
                versions = backend.package_versions(packages, names[0], role, arch)
                # Node components share the requested build; auxiliary CRI/CNI
                # packages retain their independent version numbering.
                for name in names[1:]:
                    available = set(backend.package_versions(packages, name, role, arch))
                    versions = [v for v in versions if v in available]
                return ('k8s_patch_versions', context, versions, '')
            except Exception as exc:
                return ('k8s_patch_versions', context, [], core.redact_text(str(exc)))
        self._query_jobs().submit('k8s-patches', work)

    def _receive_k8s_patch_versions(self, context, versions, error):
        self.__dict__.setdefault('_k8s_patch_running', set()).discard(context)
        if not error:
            self.__dict__.setdefault('_k8s_patch_cache', {})[context] = versions
        if context != self._k8s_patch_context():
            return
        self.package_version_combo['values'] = ('Latest', *versions)
        # A restored explicit pin must never silently become Latest.
        self.k8s_patch_status_var.set(('Could not load versions: ' + error + '. Use Refresh versions to retry.') if error else
            (f'{len(versions)} exact builds available. Latest follows this repository; select a build to pin it.' if versions else
             'No common package builds found. Check the selected repository and architecture.'))

    def _k8s_advice_changed(self, *_args):
        self.advisories_acknowledged_var.set(False)
        self._update_k8s_knowledge_note()
        self._render_kubernetes_advice()

    def _apply_vks_baseline_sources(self):
        if 'pin_to_inventory_baseline_var' not in self.__dict__:
            return
        active = self._workload().key == VKS_KEY and self.pin_to_inventory_baseline_var.get()
        changed = False
        for repo in self.repo_rows:
            if active and rolling_source(repo) and repo.enabled:
                repo.enabled = False; repo._baseline_disabled = True; changed = True
            elif not active and getattr(repo, '_baseline_disabled', False):
                repo.enabled = True; repo._baseline_disabled = False; changed = True
        if changed:
            self.loaded_signature = None; self.loaded_packages = []; self.last_result = None
            self._refresh_repo_tree_if_open(); self._update_source_status()

    def _build_kubernetes_review(self, parent):
        self.k8s_review = self._card(parent, 'Workload advisories', pady=(12, 0))
        self.k8s_review_var = tk.StringVar(value='')
        ttk.Label(self.k8s_review, textvariable=self.k8s_review_var, style='PanelHint.TLabel', wraplength=730).pack(fill='x')
        check = self._image_checkbutton(self.k8s_review, self.advisories_acknowledged_var,
                                        'I have reviewed these advisories',
                                        command=self._sync_review_action_states)
        self._register_operation_control(check)
        self._set_card_visible(self.k8s_review, False)

    def _render_kubernetes_advice(self):
        if 'k8s_review_var' not in self.__dict__:
            return
        context = BuildRequestMixin._selected_workload_context(self)
        if not context.active:
            self._set_card_visible(self.k8s_review, False); return
        self._set_card_visible(self.k8s_review, True)
        try:
            context.validate()
            result = self.__dict__.get('last_result')
            packages = result.selected if result else self.__dict__.get('selected_packages', [])
            data = report(context, packages)
            rows = data['findings'] + data['platform_advisories']
            text = '\n'.join(f"{f['severity'].upper()} · {f['package']} {f['version']}: {f['message']}" for f in rows)
            # "cluster state is unverified" implied Feathered might otherwise
            # verify a cluster. It never can: it builds bundles for a target on
            # the far side of an air gap and has no cluster access at any point.
            # Say what was assumed and what to enter instead.
            text += ('\nNo API server minors were entered, so skew was evaluated assuming every API server '
                     f'runs {parse(context.minor).line}. Enter your cluster\'s oldest and newest API server '
                     'minors on Repositories for an evaluation against the real control plane.'
                     ) if data['apiserver_assumed'] and context.workload in KUBERNETES_KEYS else ''
            if not result:
                text += '\nAnalyze to include findings for the complete resolved package set.'
            self.k8s_review_var.set(text.strip() or 'No package advisories for this selection.')
            scope = (context.workload, context.minor, context.oldest, context.newest,
                     tuple((f['package'], f['version'], f['code'], f['message']) for f in rows))
            previous = self.__dict__.get('_k8s_advice_scope')
            self._k8s_advice_scope = scope
            if previous is not None and previous != scope:
                self.advisories_acknowledged_var.set(False)
        except ValueError as exc:
            self.k8s_review_var.set(str(exc))

    def _kubernetes_build_allowed(self):
        if 'k8s_review_var' not in self.__dict__:
            return True
        self._render_kubernetes_advice()
        context = BuildRequestMixin._selected_workload_context(self)
        if not context.active:
            return True
        try:
            context.validate()
            result = self.__dict__.get('last_result')
            data = report(context, result.selected if result else self.__dict__.get('selected_packages', []))
            return context.acknowledged or not any(f['severity'] == 'conflict' for f in data['findings'])
        except ValueError:
            return False
