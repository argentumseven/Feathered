"""Application-wide worker, cancellation, progress, and event-loop coordination.

"""

from feathered_app.context import (
    ACCENT,
    APP_TITLE,
    APP_VERSION,
    ERR_FG,
    FG_MUTED,
    FG_TEXT,
    Path,
    WARN_FG,
    queue,
    redact_text,
    tk,
)
from feathered_app.activity_log import open_activity_log
from feathered_app.status_text import condense_status_text
from feathered_app.ui.theme import messagebox


class OperationsMixin:
    """Application-wide worker, cancellation, progress, and event-loop coordination."""

    @staticmethod
    def _operation_control_state(widget) -> str:
        """Read a control's state, including drawn (non-ttk) checkbuttons.

        `_image_checkbutton` returns a tk.Frame, which has no -state option.
        Reading `cget("state")` on one raises, and the lock treats that as a
        dead widget and unregisters it, so the control would stay live during
        a build. Drawn controls carry `_feather_state` instead.
        """
        reader = getattr(widget, "_feather_state", None)
        if callable(reader):
            return str(reader())
        return str(widget.cget("state"))

    @staticmethod
    def _set_operation_control_state(widget, state: str) -> None:
        setter = getattr(widget, "_feather_set_enabled", None)
        if callable(setter):
            setter(str(state) != "disabled")
            return
        widget.configure(state=state)

    def _register_operation_control(self, widget):
        """Register a button that starts a long-running operation.

        one expensive/networked operation
        owns the application at a time. Navigation remains available, but other
        process starters are disabled so checksum inspection cannot overlap a
        package catalog scan, analysis, source probe, repository rebuild, etc.
        """
        self._operation_controls.add(widget)
        if self.active_operation is not None:
            try:
                self._operation_saved_states.setdefault(
                    widget, self._operation_control_state(widget))
                self._set_operation_control_state(widget, "disabled")
            except tk.TclError:
                pass
        return widget

    def _unregister_operation_control(self, widget):
        self._operation_controls.discard(widget)
        self._operation_saved_states.pop(widget, None)

    def _set_footer_status(self, text: object) -> str:
        """Write the footer status line, condensed so it cannot grow the footer.

        The footer packs against the window bottom and its label wraps on width,
        so an unbounded message grows the footer upward and squeezes the wizard
        pane. Every write goes through here; the label additionally carries a
        fixed height so a future caller that bypasses this cannot reintroduce
        the growth.

        Returns the text actually shown, so callers can tell whether the
        operator is seeing the whole message or needs the Log.
        """
        shown = condense_status_text(text)
        var = self.__dict__.get("status_var")
        if var is not None:
            try:
                var.set(shown)
            except tk.TclError:
                pass
        return shown

    def _render_activity_status(self):
        """Render the footer operation state without conflating liveness and work."""
        state = self.__dict__.get(
            "_activity_state", "active" if self.active_operation is not None else "idle")
        if self.active_operation is None and state not in {"failed"}:
            return
        frame = int(self.__dict__.get("_activity_frame", 0))
        detail = self.__dict__.get("_operation_detail", "") or self.active_operation_label
        if state == "waiting":
            prefix = "Review required"
            colour = WARN_FG
        elif state == "failed":
            prefix = "Failed"
            colour = ERR_FG
        elif state == "active":
            prefix = "Working"
            colour = FG_TEXT
        else:
            prefix = ""
            colour = FG_MUTED

        if prefix:
            # State owns the prefix.  Older/custom callers may still pass a
            # fully composed message; strip the repeated state label so the
            # footer never renders e.g. "Review required - Review required …".
            normalized_detail = str(detail or "").strip()
            lowered = normalized_detail.casefold()
            prefix_lower = prefix.casefold()
            if lowered == prefix_lower:
                normalized_detail = ""
            elif lowered.startswith(prefix_lower):
                normalized_detail = normalized_detail[len(prefix):].lstrip(" 	–-:·")
            self._set_footer_status(
                f"{prefix}  |  {normalized_detail}" if normalized_detail else prefix)
        label = self.__dict__.get("status_label")
        if label is not None:
            try:
                label.configure(foreground=colour)
            except (tk.TclError, AttributeError):
                pass
        indicator = self.__dict__.get("activity_indicator")
        if indicator is not None:
            try:
                indicator.render_frame(frame, active=(state == "active"), state=state)
            except (tk.TclError, AttributeError, TypeError):
                # Compatibility with lightweight test indicators that predate
                # the explicit state keyword.
                try:
                    indicator.render_frame(frame, active=(state == "active"))
                except (tk.TclError, AttributeError):
                    pass
        for label in list(self.__dict__.get("_evidence_testing_labels", []) or []):
            try:
                if label.winfo_exists():
                    if state == "waiting":
                        label.configure(text="Waiting", foreground=WARN_FG)
                    elif state == "failed":
                        label.configure(text="Failed", foreground=ERR_FG)
                    else:
                        label.configure(text="Testing", foreground=ACCENT)
            except (tk.TclError, AttributeError):
                pass
        for testing_indicator in list(self.__dict__.get("_evidence_testing_indicators", []) or []):
            try:
                if testing_indicator.winfo_exists():
                    try:
                        testing_indicator.render_frame(frame, active=(state == "active"), state=state)
                    except TypeError:
                        testing_indicator.render_frame(frame, active=(state == "active"))
            except (tk.TclError, AttributeError):
                pass

    def _cancel_activity_timer(self):
        job = self.__dict__.get("_activity_job")
        self.__dict__["_activity_job"] = None
        if job is not None and self.__dict__.get("tk") is not None:
            try:
                self.after_cancel(job)
            except tk.TclError:
                pass

    def _activity_tick(self):
        self.__dict__["_activity_job"] = None
        if self.active_operation is None or self.__dict__.get("_activity_state", "idle") != "active":
            return
        self.__dict__["_activity_frame"] = (int(self.__dict__.get("_activity_frame", 0)) + 1) % 24
        self._render_activity_status()
        if self.__dict__.get("tk") is not None:
            # ~9 fps is enough for a tiny status rail and keeps redraw overhead
            # negligible compared with network/package work.
            self.__dict__["_activity_job"] = self.after(110, self._activity_tick)

    def _start_activity_animation(self):
        if self.__dict__.get("_activity_job") is not None:
            return
        self.__dict__["_activity_state"] = "active"
        self.__dict__["_activity_frame"] = 0
        self._render_activity_status()
        # Lightweight backend/unit-test instances intentionally do not create
        # a Tk interpreter. They still get the visible Working state, but no
        # timer is scheduled until a real GUI exists.
        if self.__dict__.get("tk") is not None:
            self.__dict__["_activity_job"] = self.after(110, self._activity_tick)

    def _stop_activity_animation(self, *, state: str = "idle"):
        self._cancel_activity_timer()
        self.__dict__["_activity_state"] = state
        indicator = self.__dict__.get("activity_indicator")
        if indicator is not None:
            try:
                indicator.render_frame(0, active=False, state=state)
            except (tk.TclError, AttributeError, TypeError):
                try:
                    indicator.render_frame(0, active=False)
                except (tk.TclError, AttributeError):
                    pass

    def _paint_activity(self, active: bool):
        if active:
            self._start_activity_animation()
        else:
            self._stop_activity_animation(state="idle")
            label = self.__dict__.get("status_label")
            if label is not None:
                try:
                    label.configure(foreground=FG_MUTED)
                except (tk.TclError, AttributeError):
                    pass

    def _set_operator_wait(self, detail: str):
        """Pause the visual work state while a worker waits for user input."""
        if self.active_operation is None:
            return
        self._operation_detail = str(detail)
        self._cancel_activity_timer()
        self.__dict__["_activity_state"] = "waiting"
        self._render_activity_status()

    def _resume_after_operator_wait(self, detail: str | None = None):
        """Resume active indication after a blocking operator decision."""
        if self.active_operation is None:
            return
        if detail is not None:
            self._operation_detail = str(detail)
        self.__dict__["_activity_state"] = "active"
        self._render_activity_status()
        if self.__dict__.get("_activity_job") is None and self.__dict__.get("tk") is not None:
            self.__dict__["_activity_job"] = self.after(110, self._activity_tick)

    def _operation_status(self, text: str):
        """Set footer text while preserving the current operation-state semantics."""
        if self.active_operation is not None:
            self._operation_detail = str(text)
            self._render_activity_status()
        else:
            self._operation_detail = ""
            self._set_footer_status(text)

    def _lock_operation_controls(self):
        for widget in list(self._operation_controls):
            try:
                if not widget.winfo_exists():
                    self._unregister_operation_control(widget)
                    continue
                self._operation_saved_states.setdefault(
                    widget, self._operation_control_state(widget))
                self._set_operation_control_state(widget, "disabled")
            except (tk.TclError, AttributeError):
                self._unregister_operation_control(widget)

    def _unlock_operation_controls(self):
        saved = dict(self._operation_saved_states)
        self._operation_saved_states.clear()
        for widget, state in saved.items():
            try:
                if widget.winfo_exists():
                    self._set_operation_control_state(widget, state)
            except (tk.TclError, AttributeError):
                pass
        # Several controls have semantic state beyond the saved value. Re-run
        # those normal synchronizers after the global lock is released.
        sync = getattr(self, "_sync_review_action_states", None)
        if callable(sync):
            sync()
        if self.__dict__.get("version_scan_btn") is not None:
            try:
                self._sync_package_version_control()
            except Exception:
                pass
        # Re-apply strategy-specific evidence semantics after restoring saved
        # widget states. Otherwise a globally locked button could be restored to
        # normal even though Minimal/Basic/Strict is currently selected.
        sync_evidence = getattr(self, "_update_provenance_evidence_state", None)
        if callable(sync_evidence):
            try:
                sync_evidence()
            except Exception:
                pass

    def _claim_operation(self, key: str, label: str, cancellable: bool = False) -> bool:
        if self.active_operation is not None or self.worker is not None:
            current = self.active_operation_label or "another operation"
            self._operation_status(f"{current} is already running. Wait for it to finish before starting another process.")
            return False
        self.active_operation = key
        self.active_operation_label = label.rstrip(" .…")
        self._operation_cancellable = bool(cancellable)
        self.cancel_event.clear()
        self.progress_var.set(0)
        self._lock_operation_controls()
        if self.__dict__.get("cancel_btn") is not None:
            self.cancel_btn.configure(state="normal" if cancellable else "disabled")
        self._paint_activity(True)
        self._operation_status(label)
        return True

    def _release_operation(self, final_status: str | None = None, *, outcome: str = "idle"):
        # The worker is finished, so widget reads are safe again. Dropping the
        # snapshot keeps a later build from resolving against a stale target.
        release_inputs = getattr(self, "_release_build_inputs", None)
        if callable(release_inputs):
            release_inputs()
        self.active_operation = None
        self.active_operation_label = ""
        self._operation_detail = str(final_status or "")
        self._operation_cancellable = False
        if self.__dict__.get("cancel_btn") is not None:
            self.cancel_btn.configure(state="disabled")
        self._unlock_operation_controls()
        if outcome == "failed":
            self._cancel_activity_timer()
            self.__dict__["_activity_state"] = "failed"
            self._render_activity_status()
        else:
            self._paint_activity(False)
            if final_status is not None:
                self._set_footer_status(final_status)

    def _busy(self) -> bool:
        """Guard concurrent long-running work with a persistent footer reason."""
        if self.active_operation is None and self.worker is None:
            return False
        current = self.active_operation_label or "Another operation"
        self._operation_status(f"{current} is still running. Wait for it to finish before starting another process.")
        return True

    def _begin_worker(self, status):
        # Callers already use _busy(), but keep this defensive so every future
        # worker participates in the same application-wide lease.
        if self.active_operation is None:
            if not self._claim_operation("worker", status, cancellable=True):
                return False
        else:
            self._operation_status(status)
        return True

    def _worker_done(self, ok, message, output_path=None):
        # Typed outcome: workers report ok as True (success), False (failure)
        # or "cancelled".  The string comparison below remains only as a
        # compatibility shim for older callers still using the string protocol.
        message = redact_text(str(message))
        cancelled = (ok == "cancelled") or (not ok and message in ("Operation cancelled", "Cancelled"))
        succeeded = ok is True
        failed = not succeeded and not cancelled
        self.worker = None
        stop_glow = getattr(self, "_stop_review_work_glow", None)
        if callable(stop_glow):
            stop_glow()
        release = getattr(self, "_release_operation", None)
        if callable(release):
            release(message, outcome=("failed" if failed else "idle"))
        else:  # compatibility for lightweight tests/callers without full App UI
            if getattr(self, "cancel_btn", None):
                self.cancel_btn.configure(state="disabled")
            sync = getattr(self, "_sync_review_action_states", None)
            if callable(sync):
                sync()
            elif getattr(self, "analyze_btn", None) and getattr(self, "build_btn", None):
                self.analyze_btn.configure(state="normal")
                self.build_btn.configure(state="normal")
            if getattr(self, "status_var", None):
                # Compatibility path for lightweight hosts without the full
                # mixin; condense regardless so no caller can grow the footer.
                setter = getattr(self, "_set_footer_status", None)
                if callable(setter):
                    setter(message)
                else:
                    self.status_var.set(condense_status_text(message))
        self.progress_var.set(100 if succeeded else 0)
        self._log(("DONE: " if succeeded else "CANCELLED: " if cancelled else "ERROR: ") + message)
        # only a successful publication
        # enables navigation. Analysis completion does not manufacture a path.
        if succeeded and output_path:
            candidate = Path(output_path)
            self.last_output_path = candidate
            if getattr(self, "open_output_btn", None):
                self.open_output_btn.configure(state="normal" if candidate.is_dir() else "disabled")
            if getattr(self, "review_labels", None) and "Bundle path" in self.review_labels:
                self.review_labels["Bundle path"].configure(text=str(candidate))
        if failed:
            messagebox.showerror(APP_TITLE, message)
        elif succeeded and message.startswith("ZIP ready:"):
            messagebox.showinfo(APP_TITLE, message)

    def report_callback_exception(self, exc_type, exc_value, exc_tb):
        """Handle an unhandled exception raised inside a Tk callback.

        Tkinter's default prints a traceback to stderr. Feathered ships as a
        windowed Windows executable with no console, so that output goes
        nowhere: the operator sees a UI that has silently stopped working and
        has nothing to send anyone. That is how the 1.2.10 review-dialog soft
        lock became unreportable as well as unescapable.

        So: release any grab first, because a modal grab held by a half-built
        window is what turns a crash into a lock; then record the failure where
        it can be retrieved, in the activity log and its host-side file; then
        say so plainly, including the log path.
        """
        import traceback

        # A failing repaint can raise on every redraw. Reporting the first one
        # is essential; stacking modal dialogs behind it makes the application
        # unusable for a second time, in a second way.
        if self.__dict__.get("_reporting_callback_exception"):
            return
        self.__dict__["_reporting_callback_exception"] = True
        self._release_stuck_grab()
        detail = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            self._log("Feathered hit an unexpected error in the interface:")
            for line in detail.rstrip().splitlines():
                self._log("    " + line)
        except Exception:
            pass
        location = ""
        sink = self.__dict__.get("_activity_log_sink")
        if sink:
            location = f"\n\nA full copy was written to:\n{sink.path}"
        try:
            self._set_footer_status(
                f"Unexpected interface error: {exc_type.__name__}: {exc_value}")
            messagebox.showerror(
                APP_TITLE,
                f"Feathered hit an unexpected error in the interface.\n\n"
                f"{exc_type.__name__}: {exc_value}\n\n"
                f"The window should still respond. Open Log for the full "
                f"traceback.{location}")
        except Exception:
            pass
        finally:
            self.__dict__["_reporting_callback_exception"] = False

    def _release_stuck_grab(self):
        """Drop a modal grab so the main window stays usable after a failure.

        A Toplevel that called grab_set() and then failed before wiring its
        close handler holds every click in the application. Releasing the grab
        is what turns an unrecoverable lock into a visible error.
        """
        try:
            holder = self.grab_current()
        except Exception:
            return
        if holder is None:
            return
        try:
            holder.grab_release()
        except Exception:
            pass
        if holder is not self:
            try:
                holder.destroy()
            except Exception:
                pass

    def _activity_log_file(self):
        """The host-side log sink, opened once per session.

        Opened lazily so a headless or partially constructed host never touches
        the filesystem, and cached as False on failure so an unusable profile
        directory is not retried on every log line.
        """
        sink = self.__dict__.get("_activity_log_sink")
        if sink is not None:
            return sink or None
        resolve = getattr(self, "_user_state_dir", None)
        try:
            directory = resolve() if callable(resolve) else None
            sink = open_activity_log(directory, header=f"{APP_TITLE} {APP_VERSION}")
        except Exception:
            sink = None
        self.__dict__["_activity_log_sink"] = sink or False
        if sink is None:
            self.log_lines.append(
                "Host-side activity log unavailable; diagnostics for this session "
                "exist only in this window.")
        return sink

    def _log(self, msg):
        # Final GUI log sink: workers and exception handlers must not be able to
        # bypass repository credential redaction by logging raw exception text.
        # The host-side file is fed from here, after redaction, for the same
        # reason: a build that crashes must still leave a diagnostic behind, and
        # it must not leave credentials in it.
        lines = redact_text(str(msg)).rstrip().splitlines()
        for line in lines:
            self.log_lines.append(line)
            if len(self.log_lines) > 5000: self.log_lines = self.log_lines[-4000:]
        # Lightweight hosts (contract tests, embedders) exercise redaction
        # without a filesystem; the durable mirror is additive, never required.
        resolve = getattr(self, "_activity_log_file", None)
        if lines and callable(resolve):
            sink = resolve()
            if sink is not None and not sink.write_lines(lines):
                self.log_lines.append(
                    f"Host-side activity log stopped: {sink.disabled_reason}")

    def _progress(self, label, value):
        self.events.put(("progress", label, value))

    def _drain_events(self):
        """Drain worker events without allowing one bad UI handler to kill the pump."""
        try:
            while True:
                try:
                    kind, *data = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if kind == "progress":
                        self._operation_status(data[0]); self.progress_var.set(data[1] * 100)
                    elif kind in {"checksum_inspection_finished", "checksum_inspection_progress"}:
                        data[0](*data[1:])
                    elif kind == "k8s_observation":
                        self._receive_k8s_observation(*data)
                    elif kind == "k8s_knowledge":
                        self._receive_k8s_knowledge(*data)
                    elif kind == "k8s_observation_progress":
                        self._receive_k8s_observation(*data, complete=False)
                    elif kind == "k8s_patch_versions":
                        self._receive_k8s_patch_versions(*data)
                    elif kind == "scoped_package_versions":
                        self._receive_package_versions(*data)
                    elif kind == "profile_versions":
                        if self._profile().key == data[0]:
                            self._set_release_choices(data[1])
                    elif kind == "versions":
                        self._set_release_choices(data[0])
                    elif kind == "release_report":
                        self.show_release_report(data[0])
                    elif kind == "package_versions":
                        self.package_version_combo["values"] = data[0]
                        if self.package_version_var.get() not in data[0]: self.package_version_var.set("Latest")
                    elif kind == "single_catalog": self._receive_single_catalog(*data)
                    elif kind == "probe": self._apply_probe(*data)
                    elif kind == "warnings": self._apply_warnings(data[0])
                    elif kind == "item": self._apply_item_event(data[0], data[1], data[2])
                    elif kind == "download_plan":
                        acknowledged = data[2] if len(data) > 2 else None
                        try:
                            self._apply_download_plan(data[0], data[1])
                        finally:
                            if acknowledged is not None:
                                acknowledged.set()
                    elif kind == "transfer_begin": self._begin_transfer(data[0], data[1])
                    elif kind == "probe_report": self.show_probe_report(data[0])
                    elif kind == "package_coverage": self._apply_package_source_coverage(data[0], data[1])
                    elif kind == "evidence_preflight": self._apply_evidence_preflight_results(data[0])
                    elif kind == "codenames": self._apply_discovered_codenames(data[0], data[1])
                    elif kind == "workload_aliases": self._record_workload_aliases(data[0])
                    elif kind == "cache_release_state": self._cache_release_state(data[0], data[1], data[2], data[3], data[4])
                    elif kind == "auto_release_state": self._apply_auto_release_state(data[0], data[1], data[2], data[3])
                    elif kind == "auto_release_finished": self._finish_auto_release_refresh(data[0] if data else "")
                    elif kind == "result": self._show_result(data[0])
                    elif kind == "tool_progress":
                        label, value = data[0], float(data[1])
                        self._operation_status(label)
                        if getattr(self, "repo_tool_progress_var", None) is not None:
                            self.repo_tool_progress_var.set(value * 100)
                        self.progress_var.set(value * 100)
                    elif kind == "tool_rebuild_done": self._apply_tool_rebuild_done(bool(data[0]), data[1])
                    elif kind == "tool_bundle_done": self._apply_tool_bundle_done(bool(data[0]), data[1])
                    elif kind == "done":
                        self._worker_done(data[0], data[1] if len(data) > 1 else "",
                                          data[2] if len(data) > 2 else None)
                    if self.active_operation is not None:
                        self._lock_operation_controls()
                except Exception as exc:
                    # A stale/destroyed widget or a handler bug must not strand
                    # later events (especially ``done``) or permanently hold the
                    # application-wide operation lease.
                    try:
                        self._log(
                            f"UI event handler failed for {kind!r}: "
                            f"{type(exc).__name__}: {exc}")
                    except Exception:
                        # Logging is itself UI-adjacent; keep the event pump alive
                        # even if the sink is the component that failed.
                        pass
        finally:
            # Always preserve liveness.  TclError here normally means the root
            # has been destroyed, in which case there is intentionally no pump.
            try:
                self.after(100, self._drain_events)
            except tk.TclError:
                pass

    def cancel(self):
        self.cancel_event.set(); self._operation_status("Cancelling…")
