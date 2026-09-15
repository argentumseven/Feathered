"""Root layout, navigation, scrolling, validation routing, and widget helpers.

"""

from feathered_app.context import (
    ACCENT,
    ACCENT_DIM,
    ACCENT_TEXT,
    APP_SUBTITLE,
    APP_TITLE,
    APP_VERSION,
    AcquisitionIntent,
    BG_APP,
    BG_DISABLED,
    BG_HEADER,
    BG_INPUT,
    BG_PANEL,
    BG_RAIL,
    BG_RAIL_ACTIVE,
    FG_DIM,
    FOOTER_STATUS_LINES,
    FG_MUTED,
    FG_TEXT,
    LINE,
    LINE_DISABLED,
    WARN_FG,
    evaluate_source_readiness,
    math,
    redact_text,
    time,
    tk,
    ttk,
)
from feathered_app.ui.theme import FeatheredActivityPulse, FeatheredMark, draw_feather, messagebox


class LayoutMixin:
    """Root layout, navigation, scrolling, validation routing, and widget helpers."""

    def _style(self):
        """Dark theme.

        Forces the 'clam' ttk theme. The native Windows themes (vista/xpnative)
        draw their own widget backgrounds and ignore style colours, so a dark
        palette layered over them yields unreadable results -- notably white
        text on a white button for a selected item. Anything that must be
        reliably coloured uses classic tk widgets, which honour fg/bg anywhere.
        """
        style = ttk.Style(self)
        style.theme_use("clam")
        self.configure(background=BG_APP)

        style.configure(".", background=BG_PANEL, foreground=FG_TEXT, fieldbackground=BG_INPUT,
                        bordercolor=LINE, lightcolor=BG_PANEL, darkcolor=BG_PANEL,
                        troughcolor=BG_INPUT, focuscolor=ACCENT)
        style.configure("TFrame", background=BG_APP)
        style.configure("Panel.TFrame", background=BG_PANEL)
        style.configure("TLabel", background=BG_APP, foreground=FG_TEXT, font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=BG_PANEL, foreground=FG_TEXT)
        style.configure("Hint.TLabel", background=BG_APP, foreground=FG_MUTED, font=("Segoe UI", 9))
        style.configure("PanelHint.TLabel", background=BG_PANEL, foreground=FG_MUTED,
                        font=("Segoe UI", 9))
        # Use explicit muted styles for disabled provenance controls.
        style.configure("MutedPanel.TLabel", background=BG_PANEL, foreground=FG_DIM)
        style.configure("MutedPanelHint.TLabel", background=BG_PANEL, foreground=FG_DIM,
                        font=("Segoe UI", 9))
        style.configure("PanelGroup.TLabel", background=BG_PANEL, foreground=ACCENT,
                        font=("Segoe UI Semibold", 9))
        style.configure("MutedPanelGroup.TLabel", background=BG_PANEL, foreground=FG_DIM,
                        font=("Segoe UI Semibold", 9))
        style.configure("PaneTitle.TLabel", background=BG_APP, foreground=FG_TEXT,
                        font=("Segoe UI Semibold", 15))
        style.configure("Group.TLabel", background=BG_APP, foreground=ACCENT,
                        font=("Segoe UI Semibold", 9))
        style.configure("Value.TLabel", background=BG_PANEL, foreground=FG_TEXT,
                        font=("Segoe UI Semibold", 10))
        style.configure("Attention.TLabel", background=BG_PANEL, foreground=WARN_FG,
                        font=("Segoe UI Semibold", 9))
        # Referenced by the mirror-conflict row but never configured, so ttk
        # silently inherited TLabel and painted BG_APP inside a BG_PANEL card.
        # The row was then given BG_APP to match, which rendered the whole
        # block as a dark rectangle inside the card instead of fixing it.
        style.configure("FieldLabel.TLabel", background=BG_PANEL, foreground=FG_TEXT,
                        font=("Segoe UI Semibold", 9))

        # clam's Checkbutton.indicator has no -indicatorcolor option; that name
        # belongs to the aqua/default themes. Setting it here was a silent no-op
        # and left -indicatorbackground at its clam default of #ffffff, so every
        # plain ttk.Checkbutton drew a white box with a black tick against the
        # dark palette. The real option names are below. Prefer
        # _image_checkbutton for new controls so one drawn checkbox is used
        # everywhere; these values only keep a stray ttk indicator legible.
        style.configure("TCheckbutton", background=BG_PANEL, foreground=FG_TEXT,
                        indicatorbackground=BG_INPUT, indicatorforeground=ACCENT_TEXT,
                        upperbordercolor=FG_DIM, lowerbordercolor=FG_DIM, focuscolor=BG_PANEL)
        style.map("TCheckbutton", background=[("active", BG_PANEL)],
                  foreground=[("disabled", FG_DIM)],
                  indicatorbackground=[("selected", ACCENT), ("disabled", BG_DISABLED),
                                       ("!selected", BG_INPUT)],
                  indicatorforeground=[("selected", ACCENT_TEXT)],
                  upperbordercolor=[("selected", ACCENT), ("disabled", LINE_DISABLED)],
                  lowerbordercolor=[("selected", ACCENT), ("disabled", LINE_DISABLED)])

        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG_TEXT,
                        insertcolor=FG_TEXT, bordercolor=LINE, padding=5)
        style.configure("Attention.TEntry", fieldbackground=BG_INPUT, foreground=FG_TEXT,
                        insertcolor=FG_TEXT, bordercolor=WARN_FG, lightcolor=WARN_FG,
                        darkcolor=WARN_FG, padding=5)
        # -background is NOT -fieldbackground. clam paints the four corner
        # pixels of the border with -background, and its own TEntry map sets
        # -background to the light #dcdad5 frame colour in the readonly state.
        # Leaving that unmapped put four pale dots on the corners of every
        # readonly entry (differential baseline, repo tool, bundle check,
        # mirror catalog). clam also maps -lightcolor/-darkcolor to a blue
        # #6f9dc6 on focus, which drew a blue inner ring on a green-accent UI.
        style.configure("TEntry", background=BG_PANEL)
        style.map("TEntry",
                  fieldbackground=[("disabled", BG_DISABLED)],
                  background=[("readonly", BG_PANEL), ("disabled", BG_PANEL)],
                  foreground=[("disabled", FG_DIM)],
                  lightcolor=[("focus", ACCENT)], darkcolor=[("focus", ACCENT)],
                  bordercolor=[("focus", ACCENT), ("disabled", LINE_DISABLED)])

        style.configure("TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
                        foreground=FG_TEXT, arrowcolor=FG_MUTED, bordercolor=LINE, padding=5)
        style.configure("Attention.TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
                        foreground=FG_TEXT, arrowcolor=WARN_FG, bordercolor=WARN_FG,
                        lightcolor=WARN_FG, darkcolor=WARN_FG, padding=5)
        style.map("TCombobox",
                  fieldbackground=[("disabled", BG_DISABLED), ("readonly", BG_INPUT)],
                  background=[("disabled", BG_DISABLED)],
                  foreground=[("disabled", FG_DIM), ("readonly", FG_TEXT)],
                  arrowcolor=[("disabled", FG_DIM)],
                  bordercolor=[("focus", ACCENT), ("disabled", LINE_DISABLED)])
        style.configure("Evidence.TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
                        foreground=FG_TEXT, arrowcolor=FG_MUTED, bordercolor=LINE, padding=5)
        style.map("Evidence.TCombobox",
                  fieldbackground=[("disabled", BG_DISABLED), ("readonly", BG_INPUT)],
                  background=[("disabled", BG_DISABLED)],
                  foreground=[("disabled", FG_DIM), ("readonly", FG_TEXT)],
                  arrowcolor=[("disabled", FG_DIM), ("readonly", FG_MUTED)],
                  bordercolor=[("disabled", LINE_DISABLED), ("focus", ACCENT)])
        # The dropdown list is a Tk listbox and is themed through the option DB.
        self.option_add("*TCombobox*Listbox.background", BG_INPUT)
        self.option_add("*TCombobox*Listbox.foreground", FG_TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", ACCENT_TEXT)
        self.option_add("*TCombobox*Listbox.font", ("Segoe UI", 10))

        style.configure("TButton", background=BG_INPUT, foreground=FG_TEXT, bordercolor=LINE,
                        padding=(12, 7), font=("Segoe UI", 9))
        # Compact evidence-row action. Keep the font/padding below the generic
        # button metrics so the fixed action slot cannot clip glyph descenders
        # (notably the bottom of the "Clear" label on Windows/clam).
        style.configure("EvidenceClear.TButton", background=BG_INPUT, foreground=FG_TEXT,
                        bordercolor=LINE, padding=(8, 4), font=("Segoe UI", 8))
        style.configure("Attention.TButton", background=BG_INPUT, foreground=FG_TEXT,
                        bordercolor=WARN_FG, lightcolor=WARN_FG, darkcolor=WARN_FG,
                        padding=(12, 7), font=("Segoe UI Semibold", 9))
        style.map("TButton", background=[("active", BG_RAIL_ACTIVE), ("disabled", BG_PANEL)],
                  foreground=[("disabled", FG_DIM)])
        style.configure("Primary.TButton", background=ACCENT, foreground=ACCENT_TEXT,
                        bordercolor=ACCENT, font=("Segoe UI Semibold", 10), padding=(18, 9))
        style.map("Primary.TButton", background=[("active", "#5FC79A"), ("disabled", ACCENT_DIM)],
                  foreground=[("disabled", FG_DIM)])

        style.configure("Section.TLabelframe", background=BG_PANEL, padding=14, bordercolor=LINE,
                        relief="solid", borderwidth=1)
        style.configure("Section.TLabelframe.Label", background=BG_PANEL, foreground=ACCENT,
                        font=("Segoe UI Semibold", 9))
        style.configure("TLabelframe", background=BG_PANEL, bordercolor=LINE, relief="solid",
                        borderwidth=1)
        style.configure("TLabelframe.Label", background=BG_PANEL, foreground=ACCENT,
                        font=("Segoe UI Semibold", 9))

        style.configure("Treeview", background=BG_INPUT, fieldbackground=BG_INPUT,
                        foreground=FG_TEXT, bordercolor=LINE, rowheight=26, font=("Segoe UI", 9))
        style.map("Treeview", background=[("selected", ACCENT_DIM)],
                  foreground=[("selected", FG_TEXT)])
        style.configure("Treeview.Heading", background=BG_PANEL, foreground=FG_MUTED,
                        font=("Segoe UI Semibold", 9), relief="flat")
        style.map("Treeview.Heading", background=[("active", BG_RAIL_ACTIVE)])

        for pb in ("TProgressbar", "Horizontal.TProgressbar"):
            style.configure(pb, background=ACCENT, troughcolor=BG_HEADER, bordercolor=LINE,
                            lightcolor=ACCENT, darkcolor=ACCENT, thickness=6)
        # Scrollbars: clam draws a trough, a thumb and two arrow buttons, each
        # needing its own colour. Setting only background/troughcolor left pale
        # borders and native-looking arrows against the dark UI.
        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar",
                            # keep the page
                            # position indicator visibly Feathered-green at rest.
                            background=ACCENT_DIM, troughcolor=BG_HEADER,
                            bordercolor=BG_HEADER, darkcolor=ACCENT_DIM,
                            lightcolor=ACCENT_DIM, arrowcolor=ACCENT,
                            gripcount=0, relief="flat", borderwidth=0, arrowsize=13)
            style.map(f"{orient}.TScrollbar",
                      background=[("active", ACCENT), ("pressed", ACCENT)],
                      arrowcolor=[("active", FG_TEXT)])

    def _build_ui(self):
        """A wizard: one decision per stage, advanced with Back/Next.

        The earlier layout mixed a staged rail with an always-present action
        bar, so Analyze and Build sat visible during stages where they had no
        meaning. Here the stages advance and the final stage owns the actions.
        """
        header = tk.Frame(self, background=BG_HEADER)
        header.pack(fill="x")
        inner = tk.Frame(header, background=BG_HEADER)
        inner.pack(fill="x", padx=20, pady=13)
        FeatheredMark(inner, size=54, bg=BG_HEADER, scale=0.72).pack(side="left", padx=(0, 14))
        titles = tk.Frame(inner, background=BG_HEADER); titles.pack(side="left", anchor="w")
        tk.Label(titles, text=APP_TITLE, background=BG_HEADER, foreground=FG_TEXT,
                 font=("Segoe UI Light", 22)).pack(anchor="w")
        tk.Label(titles, text=f"{APP_SUBTITLE}   ·   v{APP_VERSION}", background=BG_HEADER,
                 foreground=FG_MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self.header_state = tk.Label(inner, text="", background=BG_HEADER, foreground=FG_MUTED,
                                     font=("Segoe UI", 9))
        self.header_state.pack(side="right", anchor="e")
        tk.Frame(self, background=ACCENT, height=2).pack(fill="x")

        body = tk.Frame(self, background=BG_APP); body.pack(fill="both", expand=True)
        self.rail = tk.Frame(body, background=BG_RAIL, width=206)
        self.rail.pack(side="left", fill="y"); self.rail.pack_propagate(False)
        tk.Frame(self.rail, background=BG_RAIL, height=14).pack(fill="x")
        # Stages can exceed the window height, so the content region scrolls.
        # Without this the footer (Back/Next) was pushed off-screen on the
        # taller stages and the wizard became impossible to navigate.
        scroll_host = tk.Frame(body, background=BG_APP)
        scroll_host.pack(side="left", fill="both", expand=True)
        self.content_canvas = tk.Canvas(
            scroll_host, background=BG_APP, highlightthickness=0, bd=0, yscrollincrement=18)
        vbar = ttk.Scrollbar(scroll_host, orient="vertical", command=self.content_canvas.yview)
        self.content_canvas.configure(yscrollcommand=vbar.set)
        self.content_canvas.pack(side="left", fill="both", expand=True)
        vbar.pack(side="right", fill="y")
        content = ttk.Frame(self.content_canvas, padding=(24, 18))
        self._content_window = self.content_canvas.create_window((0, 0), window=content, anchor="nw")
        def _resize_region(_event: object) -> None:
            self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))

        def _fit_width(event) -> None:
            # Keep the inner frame exactly as wide as the visible canvas.
            self.content_canvas.itemconfigure(self._content_window, width=event.width)

        content.bind("<Configure>", _resize_region)
        self.content_canvas.bind("<Configure>", _fit_width)
        # A small, low-contrast chevron that appears only when content extends
        # below the viewport. Deliberately bottom-LEFT of the content area:
        # above the Next button it would read as "click Next", which is the
        # opposite of what it means.
        self.scroll_hint = tk.Canvas(scroll_host, width=26, height=26, background=BG_APP,
                                     highlightthickness=0, bd=0)
        self._scroll_hint_phase = 0.0
        self._scroll_hint_visible = False
        self._scroll_hint_items = []
        self.bind_all("<MouseWheel>", self._on_mousewheel)
        # X11 sends wheel events as buttons 4/5 rather than <MouseWheel>.
        for button, delta in (("<Button-4>", -3), ("<Button-5>", 3)):
            self.bind_all(button, lambda e, d=delta: self._on_wheel_button(e, d))

        # Content selection determines which repository topology must be satisfied.
        self.stage_order = ["target", "packages", "repositories", "keyrings", "transfer", "review"]
        labels = {"target": "Linux Distribution", "packages": "Content",
                  "repositories": "Repositories", "keyrings": "Provenance & Keying",
                  "transfer": "Output Directories", "review": "Review & build"}
        self.panes, self.step_rows = {}, {}
        for index, key in enumerate(self.stage_order, 1):
            self.step_rows[key] = self._rail_row(index, labels[key], key)
            self.panes[key] = ttk.Frame(content)

        # repository maintenance is a
        # sidecar workflow, not a sixth wizard step.  Keep it visually separate
        # from the numbered build path so opening a utility never implies the
        # bundle configuration has advanced.
        tk.Frame(self.rail, background=LINE, height=1).pack(fill="x", padx=14, pady=(12, 8))
        tk.Label(self.rail, text="TOOLS", background=BG_RAIL, foreground=FG_DIM,
                 font=("Segoe UI Semibold", 8), anchor="w").pack(fill="x", padx=14, pady=(0, 3))
        self.tool_rows = {"tools": self._tool_rail_row("Repository utilities", "tools")}
        self.panes["tools"] = ttk.Frame(content)

        spacer = tk.Frame(self.rail, background=BG_RAIL); spacer.pack(fill="both", expand=True)
        mark = tk.Canvas(spacer, background=BG_RAIL, highlightthickness=0, bd=0, width=200, height=150)
        mark.pack(side="bottom", anchor="s")
        draw_feather(mark, 100, 80, scale=1.15, quill="#202834", vane="#1A212B",
                     barbs="#202834", tilt=-1.32)

        self._build_target_pane(self.panes["target"])
        # Build Packages first because Repositories renders the requirements
        # derived from its workload/package controls.
        self._build_packages_pane(self.panes["packages"], heading=True)
        self._build_package_source_plan_card(self.panes["packages"])
        self._build_repositories_pane(self.panes["repositories"])
        self._build_kubernetes_repository_controls(self.panes["repositories"])
        self._build_keyrings_pane(self.panes["keyrings"])
        self._build_transfer_pane(self.panes["transfer"])
        self._build_review_pane(self.panes["review"])
        self._build_tools_pane(self.panes["tools"])

        footer = tk.Frame(self, background=BG_HEADER); footer.pack(fill="x", side="bottom")
        tk.Frame(footer, background=LINE, height=1).pack(fill="x")
        fin = tk.Frame(footer, background=BG_HEADER); fin.pack(fill="x", padx=20, pady=11)
        # status and navigation use separate
        # grid columns. The action column is never surrendered to long status
        # text; messages wrap vertically inside the remaining width instead of
        # painting over Log / Back / Next.
        fin.grid_columnconfigure(1, weight=1, minsize=120)
        fin.grid_columnconfigure(2, weight=0)
        self.status_var = tk.StringVar(value="Ready")
        self.activity_indicator = FeatheredActivityPulse(fin, width=42, height=14, bg=BG_HEADER)
        self.activity_indicator.grid(row=0, column=0, sticky="w", padx=(0, 8), pady=(4, 0))
        # height is pinned in text lines so the footer can never grow into the
        # wizard pane, whatever lands in status_var. _set_footer_status condenses
        # the text as well, but the cap is what makes the geometry a guarantee
        # rather than a convention a future caller can break.
        self.status_label = tk.Label(fin, textvariable=self.status_var, background=BG_HEADER,
                                     foreground=FG_MUTED, font=("Segoe UI", 9), anchor="w",
                                     justify="left", height=FOOTER_STATUS_LINES)
        self.status_label.grid(row=0, column=1, sticky="ew")
        self._attach_tooltip(
            self.activity_indicator,
            "Operation rail. Green motion means Feathered is actively proceeding; amber and still means "
            "the build is paused for your decision; red and still means the operation failed. Active "
            "motion is driven by Tk's event loop, so it also stops if the UI thread stalls.")
        self._attach_tooltip(
            self.status_label,
            "Current Feathered operation and phase. Active work moves the rail; a paused decision state "
            "is amber and still; a failed operation is red and still.")
        actions = tk.Frame(fin, background=BG_HEADER)
        actions.grid(row=0, column=2, sticky="ne", padx=(20, 0))
        self.log_btn = ttk.Button(actions, text="Log", command=self.show_details)
        self.log_btn.pack(side="left")
        nav = tk.Frame(actions, background=BG_HEADER); nav.pack(side="left", padx=(20, 0))
        self.back_btn = ttk.Button(nav, text="‹  Back", command=self.go_back)
        self.back_btn.pack(side="left")
        self.next_btn = ttk.Button(nav, text="Next  ›", style="Primary.TButton", command=self.go_next)
        self.next_btn.pack(side="left", padx=(8, 0))

        def _wrap_footer_status(_event=None):
            # Wrapping keeps long text off the Log / Back / Next column; the
            # pinned height keeps that wrapping from growing the footer.
            try:
                width = max(120, self.status_label.winfo_width())
                self.status_label.configure(wraplength=width, height=FOOTER_STATUS_LINES)
            except tk.TclError:
                pass
        fin.bind("<Configure>", _wrap_footer_status, add="+")
        self.status_label.bind("<Configure>", _wrap_footer_status, add="+")

        meter = ttk.Frame(self, padding=(24, 0, 24, 8)); meter.pack(fill="x", side="bottom")
        self.progress_var = tk.DoubleVar(value=0)
        ttk.Progressbar(meter, variable=self.progress_var, maximum=100).pack(fill="x")
        self.show_pane("target")
        self._bind_combobox_scrolling()
        self._bind_nested_scrolling()
        self.after(400, self._animate_scroll_hint)

    def _scroll_hint_needed(self) -> bool:
        """True when there is content below the visible area."""
        canvas = getattr(self, "content_canvas", None)
        if canvas is None:
            return False
        try:
            first, last = canvas.yview()
        except tk.TclError:
            return False
        return last < 0.995 and (last - first) < 0.995

    def _animate_scroll_hint(self):
        """Continuously animate the green "more below" chevron.

        scrolling no longer pauses the hint.
        The two line items are reused instead of deleted/recreated each frame,
        so continuous animation stays cheap during rapid canvas movement.
        """
        try:
            needed = self._scroll_hint_needed()
            if needed != self._scroll_hint_visible:
                self._scroll_hint_visible = needed
                if needed:
                    self.scroll_hint.place(relx=0.0, rely=1.0, x=14, y=-12, anchor="sw")
                else:
                    self.scroll_hint.place_forget()
            if needed:
                self._scroll_hint_phase = (self._scroll_hint_phase + 0.18) % (2 * math.pi)
                offset = 2.2 * math.sin(self._scroll_hint_phase)
                c = self.scroll_hint
                mid, top = 13, 8 + offset
                coords = []
                for dy in (0, 5):
                    coords.append((mid - 6, top + dy, mid, top + 5 + dy, mid + 6, top + dy))
                if len(self._scroll_hint_items) != 2:
                    c.delete("all")
                    self._scroll_hint_items = [
                        c.create_line(*coords[0], fill=ACCENT, width=2,
                                      capstyle="round", joinstyle="round"),
                        c.create_line(*coords[1], fill=ACCENT_DIM, width=2,
                                      capstyle="round", joinstyle="round"),
                    ]
                else:
                    for item, points in zip(self._scroll_hint_items, coords):
                        c.coords(item, *points)
        except tk.TclError:
            return
        self.after(70, self._animate_scroll_hint)

    def _combobox_popdown_open(self) -> bool:
        """True while any dropdown list is showing.

        Scrolling the page underneath an open popdown leaves the list floating
        detached from its box, which looks broken; the wheel should belong to
        the list, not the page.
        """
        try:
            for combo in self._all_comboboxes():
                popdown = combo.tk.eval(f"ttk::combobox::PopdownWindow {combo}")
                if popdown and self.tk.call("winfo", "ismapped", popdown):
                    return True
        except tk.TclError:
            return False
        return False

    def _all_comboboxes(self, parent=None):
        parent = parent or self
        found = []
        for child in parent.winfo_children():
            if isinstance(child, ttk.Combobox):
                found.append(child)
            found.extend(self._all_comboboxes(child))
        return found

    def _bind_combobox_scrolling(self, parent=None):
        """Keep closed comboboxes from hijacking an in-progress page scroll.

        the previous guard simply returned
        ``break`` over every closed combobox.  Crossing one while rapidly
        scrolling the page therefore felt like the wheel had frozen.  Closed
        comboboxes now route the wheel to the page; an open popdown keeps its
        native list scrolling.
        """
        for combo in self._all_comboboxes(parent):
            self._bind_combobox_widget(combo)

    def _bind_combobox_widget(self, combo):
        combo.bind("<MouseWheel>", self._on_combobox_mousewheel)
        combo.bind("<Button-4>", lambda e: self._on_combobox_wheel_button(e, -3))
        combo.bind("<Button-5>", lambda e: self._on_combobox_wheel_button(e, 3))

    def _bind_nested_scrolling(self, parent=None):
        """Route nested scrollables before their ttk/class bindings fire."""
        parent = parent or self
        for child in parent.winfo_children():
            if isinstance(child, (ttk.Treeview, tk.Text, tk.Listbox)):
                child.bind("<MouseWheel>", self._on_nested_mousewheel)
                child.bind("<Button-4>", lambda e: self._on_nested_wheel_button(e, -3))
                child.bind("<Button-5>", lambda e: self._on_nested_wheel_button(e, 3))
            self._bind_nested_scrolling(child)

    def _on_nested_mousewheel(self, event):
        if self._combobox_popdown_open():
            return "break"
        units = self._mousewheel_units(event.delta)
        if not units:
            return "break"
        target = self._wheel_target(event, units)
        self._queue_wheel_scroll(target, units)
        return "break"

    def _on_nested_wheel_button(self, event, delta):
        if self._combobox_popdown_open():
            return "break"
        target = self._wheel_target(event, delta)
        self._queue_wheel_scroll(target, delta)
        return "break"

    def _on_combobox_mousewheel(self, event):
        if self._combobox_popdown_open():
            return None
        self._queue_wheel_scroll(self.content_canvas, self._mousewheel_units(event.delta))
        return "break"

    def _on_combobox_wheel_button(self, event, delta):
        if self._combobox_popdown_open():
            return None
        self._queue_wheel_scroll(self.content_canvas, delta)
        return "break"

    def _mousewheel_units(self, delta: int) -> int:
        """Normalize high-resolution Windows wheel/touchpad deltas.

        Small deltas are accumulated instead of being truncated to zero by
        ``delta // 120``.  That removes the dead/laggy feel on precision input
        devices and lets us coalesce repaint work below.
        """
        if not delta:
            return 0
        self._wheel_fraction += -float(delta) / 120.0
        if abs(self._wheel_fraction) < 1.0:
            return 0
        units = int(self._wheel_fraction)
        self._wheel_fraction -= units
        return max(-8, min(8, units))

    def _widget_can_scroll(self, widget, units: int) -> bool:
        if widget is None or not units:
            return False
        try:
            first, last = widget.yview()
        except (tk.TclError, TypeError, ValueError, AttributeError):
            return False
        if (last - first) >= 0.999:
            return False
        return (units > 0 and last < 0.999) or (units < 0 and first > 0.001)

    def _scrollable_under_pointer(self, event, units=0):
        """Return the innermost nested scroller that can move this direction."""
        widget = event.widget
        while widget is not None:
            if isinstance(widget, (ttk.Treeview, tk.Text, tk.Listbox)) or \
                    (isinstance(widget, tk.Canvas) and widget is not self.content_canvas):
                if self._widget_can_scroll(widget, units or 1):
                    return widget
                return None
            widget = getattr(widget, "master", None)
        return None

    def _wheel_target(self, event, units: int):
        """Capture one wheel gesture to one surface for a short dwell period."""
        now = time.monotonic()
        owner = self._wheel_owner
        if now - self._wheel_last_event < 0.20 and owner is not None:
            try:
                alive = bool(owner.winfo_exists())
            except (tk.TclError, AttributeError):
                alive = False
            if alive and (owner is self.content_canvas or self._widget_can_scroll(owner, units)):
                self._wheel_last_event = now
                return owner
        inner = self._scrollable_under_pointer(event, units)
        owner = inner if inner is not None else self.content_canvas
        self._wheel_owner = owner
        self._wheel_last_event = now
        return owner

    def _queue_wheel_scroll(self, target, units: int):
        """Batch rapid wheel events into a single Tk redraw."""
        if not units:
            return
        if self._wheel_pending_target is not None and self._wheel_pending_target is not target:
            self._flush_wheel_scroll()
        self._wheel_pending_target = target
        self._wheel_pending_units = max(-12, min(12, self._wheel_pending_units + units))
        if self._wheel_flush_job is None:
            self._wheel_flush_job = self.after(10, self._flush_wheel_scroll)

    def _flush_wheel_scroll(self):
        self._wheel_flush_job = None
        target = self._wheel_pending_target
        units = self._wheel_pending_units
        self._wheel_pending_target = None
        self._wheel_pending_units = 0
        if target is None or not units:
            return
        try:
            if target is not self.content_canvas and not self._widget_can_scroll(target, units):
                target = self.content_canvas
                self._wheel_owner = target
            target.yview_scroll(units, "units")
        except tk.TclError:
            pass

    def _on_wheel_button(self, event, delta):
        """X11 delivers wheel events as buttons 4 and 5."""
        if self._combobox_popdown_open():
            return "break"
        target = self._wheel_target(event, delta)
        self._queue_wheel_scroll(target, delta)
        return "break"

    def _on_mousewheel(self, event):
        if self._combobox_popdown_open():
            return "break"
        units = self._mousewheel_units(event.delta)
        if not units:
            return "break"
        target = self._wheel_target(event, units)
        self._queue_wheel_scroll(target, units)
        return "break"

    def _rail_row(self, number: int, label: str, key: str):
        """One clickable step, built from classic tk widgets.

        Themed ttk buttons ignore background/foreground on Windows, which is
        what produced an unreadable white-on-white selected step.
        """
        row = tk.Frame(self.rail, background=BG_RAIL, cursor="hand2"); row.pack(fill="x")
        bar = tk.Frame(row, background=BG_RAIL, width=3); bar.pack(side="left", fill="y")
        num = tk.Label(row, text=str(number), background=BG_RAIL, foreground=FG_DIM,
                       font=("Segoe UI Semibold", 9), width=3)
        num.pack(side="left", pady=11)
        text = tk.Label(row, text=label, background=BG_RAIL, foreground=FG_MUTED,
                        font=("Segoe UI", 10), anchor="w")
        text.pack(side="left", fill="x", expand=True, pady=11)
        parts = {"row": row, "bar": bar, "num": num, "text": text}

        def on_click(_event) -> None:
            self._rail_step_clicked(key)

        def on_enter(_event) -> None:
            self._rail_hover(key, True)

        def on_leave(_event) -> None:
            self._rail_hover(key, False)

        # Click AND hover must be bound on every child: Tk delivers <Leave> to
        # the row frame when the pointer crosses onto a child label, so a
        # row-only hover binding switches the highlight off exactly while the
        # pointer is over the step's text -- which reads as "the text is not
        # part of the button".
        for w in (row, bar, num, text):
            w.bind("<Button-1>", on_click)
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)
        return parts

    def _rail_step_clicked(self, key: str) -> None:
        """Navigate to any rail step from anywhere, in one click.

        Free navigation is deliberate: every stage is prepopulated with a
        valid default, and Repository utilities (outside stage_order) must be
        able to reach any step. Correctness is enforced at the terminal
        actions instead -- the Next button validates its single forward
        boundary, and Analyze/Build preflight validates every stage and
        returns to the responsible one with an attention border on failure."""
        # Free navigation: every stage is prepopulated with a valid default,
        # so the rail may jump anywhere (including from Repository utilities,
        # which sits outside stage_order). Correctness is enforced where it
        # matters: Analyze/Build preflight validates every stage and returns
        # to the responsible one with an attention border on failure. The
        # Next button still validates its single forward boundary.
        self.show_pane(key)

    def _tool_rail_row(self, label: str, key: str):
        """Non-numbered rail entry for maintenance utilities.

        tools are intentionally outside
        ``stage_order``.  They borrow the rail styling but never become a
        numbered wizard step.
        """
        row = tk.Frame(self.rail, background=BG_RAIL, cursor="hand2")
        row.pack(fill="x")
        bar = tk.Frame(row, background=BG_RAIL, width=3)
        bar.pack(side="left", fill="y")
        icon = tk.Label(row, text="◆", background=BG_RAIL, foreground=FG_DIM,
                        font=("Segoe UI", 8), width=3)
        icon.pack(side="left", pady=10)
        text = tk.Label(row, text=label, background=BG_RAIL, foreground=FG_MUTED,
                        font=("Segoe UI", 10), anchor="w")
        text.pack(side="left", fill="x", expand=True, pady=10)
        parts = {"row": row, "bar": bar, "num": icon, "text": text}

        def click(_event=None):
            self.show_pane(key)

        def hover(_event, entering: bool):
            if getattr(self, "active_pane", None) == key:
                return
            bg = BG_RAIL_ACTIVE if entering else BG_RAIL
            row.configure(background=bg)
            icon.configure(background=bg)
            text.configure(background=bg)

        # Same child-binding rule as _rail_row: hover must survive the pointer
        # crossing onto the icon/text labels.
        for widget in (row, bar, icon, text):
            widget.bind("<Button-1>", click)
            widget.bind("<Enter>", lambda e: hover(e, True))
            widget.bind("<Leave>", lambda e: hover(e, False))
        return parts

    def _rail_hover(self, key: str, entering: bool):
        if getattr(self, "active_pane", None) == key:
            return
        parts = self.step_rows[key]
        bg = BG_RAIL_ACTIVE if entering else BG_RAIL
        for name in ("row", "num", "text"):
            parts[name].configure(background=bg)

    def show_pane(self, key: str):
        """Reveal one wizard stage or sidecar utility and restyle the rail."""
        self._dismiss_tooltips()
        if key in self.stage_order:
            self.last_wizard_pane = key
        for name, parts in self.step_rows.items():
            active = name == key
            bg = BG_RAIL_ACTIVE if active else BG_RAIL
            parts["row"].configure(background=bg)
            parts["num"].configure(background=bg, foreground=ACCENT if active else FG_DIM)
            parts["text"].configure(background=bg, foreground=FG_TEXT if active else FG_MUTED,
                                    font=("Segoe UI Semibold", 10) if active else ("Segoe UI", 10))
            parts["bar"].configure(background=ACCENT if active else BG_RAIL)
        for name, parts in getattr(self, "tool_rows", {}).items():
            active = name == key
            bg = BG_RAIL_ACTIVE if active else BG_RAIL
            parts["row"].configure(background=bg)
            parts["num"].configure(background=bg, foreground=ACCENT if active else FG_DIM)
            parts["text"].configure(background=bg, foreground=FG_TEXT if active else FG_MUTED,
                                    font=("Segoe UI Semibold", 10) if active else ("Segoe UI", 10))
            parts["bar"].configure(background=ACCENT if active else BG_RAIL)
        for pane in self.panes.values():
            pane.pack_forget()
        self.panes[key].pack(fill="both", expand=True)
        self.active_pane = key
        # Navigation is structural state, so paint it before pane-specific
        # refresh work. A rendering/validation exception on Review must never
        # leave the previous step's Next button visible.
        self._sync_wizard_nav()
        if getattr(self, "content_canvas", None):
            self.content_canvas.yview_moveto(0)
        if key == "packages":
            # Workload intent is authoritative.  As soon as Packages knows the
            # selected workload, pre-seed any explicit side-channel/vendor
            # repositories it declares so Repositories opens in a satisfiable
            # state rather than making the operator repair an avoidable gap.
            if getattr(self, "selection_mode_var", None) is not None and not self._single_mode() and not self._mirror_mode():
                self._activate_workload_repository_selection()
            self._refresh_package_source_plan()
        if key == "repositories":
            self._activate_repository_universe_for_intent()
            self._render_repository_workflow()
            # Re-run the idempotent seed before rendering as a defensive guard
            # for restored sessions and programmatic navigation.  In the normal
            # path the workload selection on Packages already populated these.
            if getattr(self, "selection_mode_var", None) is not None and not self._single_mode() and not self._mirror_mode():
                self._activate_workload_repository_selection()
            self._sync_mirror_selection_card_visibility()
            self._sync_exact_package_selection_card_visibility()
            if self._mirror_mode():
                self._refresh_mirror_repos()
            self._refresh_workload_repository_views()
            self._refresh_package_source_coverage()
        if key == "keyrings":
            self._refresh_provenance_editor()
            self._refresh_vendor_signature_tree()
            self._refresh_entitlement_state()
            self._refresh_keyring_tree()
        if key == "transfer":
            self._sync_output_capability_controls()
        if key == "review":
            self._refresh_review_summary()
            if self.last_result is None:
                self._refresh_review_contract()
            self._sync_review_action_states()
        if key == "tools":
            self._refresh_tools_summary()
        self._sync_wizard_nav()
        if self.active_operation is not None:
            # Pane refreshes may recompute a button's local state. The global
            # activity lease always wins until the running process finishes.
            self._lock_operation_controls()

    def _sync_wizard_nav(self):
        if self.active_pane not in self.stage_order:
            self.next_btn.pack_forget()
            self.back_btn.configure(state="normal", text="‹  Return to build")
            self.header_state.configure(text="Repository utilities")
            return
        self.back_btn.configure(text="‹  Back")
        index = self.stage_order.index(self.active_pane)
        self.back_btn.configure(state="normal" if index > 0 else "disabled")
        if index == len(self.stage_order) - 1:
            self.next_btn.pack_forget()
            self.next_btn.configure(text="Next  ›", state="disabled")
        else:
            self.next_btn.configure(state="normal")
            self.next_btn.pack(side="left", padx=(8, 0))
            if self.active_pane == "packages":
                intent = self._acquisition_intent()
                if intent is AcquisitionIntent.PACKAGES:
                    self.next_btn.configure(text="Next: configure repositories  ›")
                elif intent is AcquisitionIntent.REPOSITORY_MIRROR:
                    self.next_btn.configure(text="Next: choose repositories  ›")
                else:
                    self.next_btn.configure(text="Next: repositories  ›")
            else:
                self.next_btn.configure(text="Next  ›")
        self.header_state.configure(text=f"Step {index + 1} of {len(self.stage_order)}")

    def _validate_wizard_transition(self, pane: str) -> tuple[bool, str, object | None]:
        """Validate the current stage before allowing forward wizard movement.

        This is intentionally limited to deterministic local prerequisites. It
        does not perform network I/O, but it does stop the wizard from reaching
        Review with an empty contract or a source plan that Build is guaranteed
        to reject later.
        """
        try:
            if pane == "target":
                if not self.release_var.get().strip():
                    raise RuntimeError("Choose or enter a Linux release before continuing.")
                if not self.arch_var.get().strip():
                    raise RuntimeError("Choose a target architecture before continuing.")
            elif pane == "packages":
                context = self._selected_workload_context()
                context.validate()
                # Workload mode creates semantic roots on this step. Exact
                # package and mirror modes intentionally choose concrete roots
                # on Repositories, so they remain valid intents here.
                if self._acquisition_intent() is AcquisitionIntent.WORKLOAD:
                    self._package_requests()
            elif pane == "repositories":
                state = self._acquisition_state()
                if state.blocked:
                    raise RuntimeError(state.reason or
                                       "The selected acquisition cannot proceed with the current repositories.")
            elif pane == "keyrings":
                self._validate_provenance_step()
                # Entitlement and other deterministic source prerequisites are
                # configured on this page. Do not defer a guaranteed source-plan
                # failure until Build.
                self._validate_source_plan()
            elif pane == "transfer":
                self._validate_output_naming()
                self._validate_signing()
                if not self._has_review_contract():
                    raise RuntimeError(
                        "Nothing is selected for this build. Return to Content/Repositories and complete the acquisition request before Review.")
            return True, "", None
        except (RuntimeError, ValueError) as exc:
            message = redact_text(str(exc))
            target = None
            if pane == "repositories":
                state = self._acquisition_state()
                if state.intent is AcquisitionIntent.PACKAGES:
                    target = getattr(self, "exact_package_selection_card", None)
                elif state.intent is AcquisitionIntent.REPOSITORY_MIRROR:
                    target = getattr(self, "mirror_selection_card", None)
                else:
                    readiness = evaluate_source_readiness(
                        self._source_plan(), self.repo_rows, tier_getter=self._repo_tier)
                    target = (getattr(self, "base_sources_card", None)
                              if "distribution" in readiness.missing_scopes or "enabled" in readiness.missing_scopes
                              else getattr(self, "workload_repositories_card", None))
            elif pane == "keyrings":
                lower = message.lower()
                if "entitlement" in lower or "private key" in lower or "repository ca" in lower:
                    target = getattr(self, "entitlement_tree", None)
                elif "checksum" in lower:
                    target = getattr(self, "prov_digest_combo", None) or getattr(self, "prov_checksum_card", None)
                else:
                    target = getattr(self, "prov_evidence_card", None)
            elif pane == "packages":
                target = getattr(self, "package_selection_card", None)
            elif pane == "transfer":
                target = getattr(self, "folder_label_entry", None) or getattr(self, "out_var", None)
            return False, message, target

    def _default_network_source_method(self) -> str:
        profile = self._profile()
        if profile.key == "rhel":
            return "Red Hat CDN entitlement (official)"
        if profile.package_family == "deb":
            return "Distribution APT repositories"
        if profile.package_family == "arch":
            return "Distribution pacman repositories"
        return "Distribution repositories"

    def _recover_wizard_transition(self, pane: str, message: str) -> bool:
        """Offer explicit alternate recovery policies for bifurcated source failures.

        Most validation failures have one corrective action and should remain
        ordinary errors. These three cases genuinely have two different source
        policies, so making the operator dismiss an error and hunt for the
        alternative is unnecessary friction.
        """
        method_var = getattr(self, "source_method_var", None)
        method = method_var.get() if method_var is not None else ""
        lower = (message or "").lower()
        profile = self._profile()

        if (profile.key == "rhel" and method == "Red Hat CDN entitlement (official)"
                and any(token in lower for token in ("entitlement", "private key", "repository ca"))):
            choice = messagebox.askchoice(
                "Red Hat source access required",
                "The official Red Hat CDN source plan needs RHSM entitlement material before Feathered can use it.\n\n"
                "Choose whether to configure the vendor entitlement or replace the base source plan with public EL-compatible fallback repositories.",
                (("entitlement", "Configure vendor entitlement"),
                 ("fallback", "Switch to fallback repositories")),
                default="entitlement", parent=self)
            if choice == "fallback":
                self.source_method_var.set("Public EL-compatible mirrors (recommended fallback)")
                self._source_method_changed()
                self.show_pane("repositories")
                target = getattr(self, "base_sources_card", None)
                if target is not None:
                    self.after(20, lambda t=target: self._scroll_to_widget(t))
                self._log("Switched from Red Hat CDN entitlement sources to public EL-compatible fallback repositories.")
            else:
                self.show_pane("keyrings")
                target = getattr(self, "entitlement_tree", None)
                if target is not None:
                    self.after(20, lambda t=target: self._scroll_to_widget(t))
            return True

        enabled_base = [r for r in getattr(self, "repo_rows", [])
                        if self._repo_tier(r) == "base" and r.enabled and str(r.url or "").strip()]
        if (method == "Installation media / local mirror (ISO, DVD, folder, SMB)"
                and not enabled_base and pane in {"repositories", "keyrings"}):
            choice = messagebox.askchoice(
                "Local media is not loaded",
                "This source plan has no loaded installation media or local mirror. Choose whether to return to Repositories and load it, or replace the source plan with the target's default network repositories.",
                (("media", "Choose / load local media"),
                 ("network", "Switch to network repositories")),
                default="media", parent=self)
            if choice == "network":
                self.source_method_var.set(self._default_network_source_method())
                self._source_method_changed()
            self.show_pane("repositories")
            target = getattr(self, "base_sources_card", None)
            if target is not None:
                self.after(20, lambda t=target: self._scroll_to_widget(t))
            return True

        if (method == "Custom repositories" and not enabled_base
                and pane in {"repositories", "keyrings"}):
            choice = messagebox.askchoice(
                "Custom base source plan is empty",
                "Custom source mode has no enabled foundational repository. Choose whether to add the intended custom base repositories or restore the target's distribution defaults.",
                (("custom", "Add custom base repositories"),
                 ("defaults", "Restore distribution defaults")),
                default="custom", parent=self)
            if choice == "defaults":
                self.source_method_var.set(self._default_network_source_method())
                self._source_method_changed()
            self.show_pane("repositories")
            target = getattr(self, "base_sources_card", None)
            if target is not None:
                self.after(20, lambda t=target: self._scroll_to_widget(t))
            return True
        return False

    def go_next(self) -> bool:
        """Advance one wizard stage. Returns True only if the stage changed."""
        if self.active_pane not in self.stage_order:
            return False
        index = self.stage_order.index(self.active_pane)
        if index >= len(self.stage_order) - 1:
            # Review is terminal. There is deliberately no seventh wizard
            # transition; its Analyze/Build controls own the next action.
            self._sync_wizard_nav()
            return False
        ok, message, target = self._validate_wizard_transition(self.active_pane)
        if not ok:
            if self._recover_wizard_transition(self.active_pane, message):
                return False
            if not self._route_validation_error(message):
                self._focus_validation(self.active_pane, target, message)
            messagebox.showerror(APP_TITLE, message)
            return False
        next_index = index + 1
        self.show_pane(self.stage_order[next_index])
        return True

    def go_back(self):
        if self.active_pane not in self.stage_order:
            self.show_pane(getattr(self, "last_wizard_pane", "review"))
            return
        index = self.stage_order.index(self.active_pane)
        if index > 0:
            self.show_pane(self.stage_order[index - 1])

    def _pane_heading(self, parent, title, hint):
        ttk.Label(parent, text=title, style="PaneTitle.TLabel").pack(anchor="w")
        ttk.Label(parent, text=hint, style="Hint.TLabel", wraplength=740).pack(anchor="w", pady=(4, 16))

    def _card(self, parent, title, pady=(0, 0)):
        """A titled panel; the title sits above the card in the accent colour."""
        holder = ttk.Frame(parent); holder.pack(fill="x", pady=pady)
        ttk.Label(holder, text=title.upper(), style="Group.TLabel").pack(anchor="w", pady=(0, 5))
        card = tk.Frame(holder, background=BG_PANEL, highlightbackground=LINE,
                        highlightthickness=1, bd=0)
        card.pack(fill="x")
        inner = ttk.Frame(card, style="Panel.TFrame", padding=14)
        inner.pack(fill="both", expand=True)
        # Keep the outer classic-Tk frame reachable for validation focus rings.
        inner._feather_card_frame = card
        # The title label and the bordered frame live on the holder, not on the
        # returned inner frame. Callers that hide a card were calling
        # pack_forget() on `inner`, which left the accent heading and a
        # collapsed 1px box on screen. Keep the holder and its pack options
        # reachable so _set_card_visible can hide and restore the whole thing.
        inner._feather_card_holder = holder
        holder._feather_pack_options = {"fill": "x", "pady": pady}
        return inner

    def _set_card_visible(self, card, visible: bool) -> None:
        """Show or hide a whole _card, heading included, keeping its position.

        Re-packing appends to the end of the parent's pack order, so a card
        hidden and shown again would migrate to the bottom of its pane. The
        original sibling is recorded on first hide and used as `before=`.
        """
        holder = getattr(card, "_feather_card_holder", card)
        try:
            if not holder.winfo_exists():
                return
            options = dict(getattr(holder, "_feather_pack_options", {"fill": "x"}))
            if visible:
                if holder.winfo_manager():
                    return
                anchor = getattr(holder, "_feather_pack_before", None)
                if anchor is not None and anchor.winfo_exists() and anchor.winfo_manager():
                    options["before"] = anchor
                holder.pack(**options)
            else:
                if not holder.winfo_manager():
                    return
                siblings = holder.master.pack_slaves()
                index = siblings.index(holder)
                holder._feather_pack_before = (
                    siblings[index + 1] if index + 1 < len(siblings) else None)
                holder.pack_forget()
        except (tk.TclError, ValueError, AttributeError):
            # Geometry bookkeeping must never take the wizard down.
            return

    def _clear_validation_attention(self, *_args) -> None:
        card = getattr(self, "_attention_card", None)
        if card is not None:
            try:
                card.configure(highlightbackground=LINE, highlightthickness=1)
            except tk.TclError:
                pass
        widget = getattr(self, "_attention_widget", None)
        if widget is not None:
            try:
                previous = getattr(self, "_attention_widget_style", None)
                if previous is not None and hasattr(widget, "configure"):
                    widget.configure(style=previous)
            except tk.TclError:
                pass
        self._attention_card = None
        self._attention_widget = None
        self._attention_widget_style = None

    def _card_for_widget(self, widget):
        node = widget
        while node is not None:
            card = getattr(node, "_feather_card_frame", None)
            if card is not None:
                return card
            node = getattr(node, "master", None)
        return None

    def _scroll_to_widget(self, widget) -> None:
        canvas = getattr(self, "content_canvas", None)
        if canvas is None or widget is None:
            return
        try:
            self.update_idletasks()
            bbox = canvas.bbox("all")
            if not bbox:
                return
            total = max(1, bbox[3] - bbox[1])
            current_top = canvas.canvasy(0)
            relative = widget.winfo_rooty() - canvas.winfo_rooty()
            target = max(0, current_top + relative - 42)
            canvas.yview_moveto(min(1.0, target / total))
        except tk.TclError:
            pass

    def _focus_validation(self, pane_key: str, widget, message: str) -> None:
        """Return to and visibly mark the control/card that blocked progress."""
        self._clear_validation_attention()
        self.show_pane(pane_key)
        self.update_idletasks()
        card = self._card_for_widget(widget)
        if card is not None:
            try:
                card.configure(highlightbackground=WARN_FG, highlightcolor=WARN_FG,
                               highlightthickness=2)
                self._attention_card = card
                # Re-assert after the pane finishes laying out: the first
                # configure can land before the card is mapped, which is what
                # left the ring grey until an unrelated event repainted it.
                self.after_idle(lambda c=card: self._reassert_attention_ring(c))
            except tk.TclError:
                pass
        try:
            previous = widget.cget("style") if widget is not None else None
            if isinstance(widget, ttk.Entry):
                widget.configure(style="Attention.TEntry")
            elif isinstance(widget, ttk.Combobox):
                widget.configure(style="Attention.TCombobox")
            elif isinstance(widget, ttk.Button):
                widget.configure(style="Attention.TButton")
            if widget is not None and previous is not None:
                self._attention_widget = widget
                self._attention_widget_style = previous
                widget.bind("<Button-1>", self._clear_validation_attention, add="+")
                widget.bind("<KeyRelease>", self._clear_validation_attention, add="+")
                widget.bind("<<ComboboxSelected>>", self._clear_validation_attention, add="+")
                try:
                    widget.focus_set()
                except tk.TclError:
                    pass
        except (tk.TclError, AttributeError):
            pass
        self.status_var.set("Needs attention: " + message)
        self.after_idle(lambda: self._scroll_to_widget(widget))

    def _reassert_attention_ring(self, card) -> None:
        if card is None or card is not getattr(self, "_attention_card", None):
            return
        try:
            card.configure(highlightbackground=WARN_FG, highlightcolor=WARN_FG,
                           highlightthickness=2)
            card.update_idletasks()
        except tk.TclError:
            pass

    def _signing_requested(self) -> None:
        """An operator enabling sealing should see any missing setup immediately."""
        if not self.sign_index_var.get():
            return
        try:
            self._validate_signing()
        except (RuntimeError, ValueError) as exc:
            self._route_validation_error(str(exc))

    def _route_validation_error(self, message: str) -> bool:
        """Map common missing-input failures back to the exact stage/control."""
        text = (message or "").lower()
        if "signing key" in text or "sealing is enabled" in text:
            target = getattr(self, "signing_key_entry", None)
            if target is not None and target.instate(["disabled"]):
                target = getattr(self, "openpgp_status_card", target)
            self._focus_validation("keyrings", target, message)
        elif "entitlement" in text or "private key" in text and "red hat" in text:
            self._focus_validation("keyrings", getattr(self, "entitlement_tree", None), message)
        elif "target inventory" in text:
            self._focus_validation("target", getattr(self, "inventory_btn", None), message)
        elif "custom label" in text or "output folder scheme" in text:
            self._focus_validation("transfer", getattr(self, "folder_label_entry", None), message)
        elif ("exact package" in text or "vks node os package addition" in text or
              any(token in text for token in ("no repositories are ticked", "at least one package",
                                               "enter at least one package", "nothing is selected"))):
            try:
                exact_mode = self._acquisition_intent() is AcquisitionIntent.PACKAGES
            except Exception:
                exact_mode = False
            vks_package_chooser = "vks node os package addition" in text
            if exact_mode or vks_package_chooser:
                self.show_pane("repositories")
                self._focus_validation(
                    "repositories", getattr(self, "exact_package_selection_card", None), message)
            else:
                self._focus_validation("packages", getattr(self, "package_selection_card", None), message)
        elif "workload repository" in text or "workload-specific repository" in text:
            self._focus_validation("repositories", getattr(self, "package_workload_repositories_card", None), message)
        elif any(token in text for token in ("base source", "package sources", "dependency repository",
                                              "distribution repository", "distribution-native",
                                              "no enabled source", "no package sources",
                                              "local media", "media folder")):
            self._focus_validation("repositories", getattr(self, "base_sources_card", None), message)
        else:
            # Unknown validation failures keep their existing stage/control.
            return False
        return True

    def _dismiss_tooltips(self) -> None:
        windows = list(self.__dict__.get("_tooltip_windows", ()))
        self.__dict__["_tooltip_windows"] = set()
        for win in windows:
            try:
                if win.winfo_exists():
                    win.destroy()
            except tk.TclError:
                pass

    def _attach_tooltip(self, widget, text: str) -> None:
        """Attach a compact hover tooltip that cannot outlive its source widget."""
        state = {"window": None}

        def hide(_event=None):
            win = state.get("window")
            if win is not None:
                self.__dict__.setdefault("_tooltip_windows", set()).discard(win)
                try:
                    win.destroy()
                except tk.TclError:
                    pass
            state["window"] = None

        def show(_event=None):
            hide()
            try:
                if not widget.winfo_ismapped():
                    return
                win = tk.Toplevel(self)
                win.wm_overrideredirect(True)
                win.attributes("-topmost", True)
                x = widget.winfo_rootx() + 18
                y = widget.winfo_rooty() + widget.winfo_height() + 6
                win.wm_geometry(f"+{x}+{y}")
                label = tk.Label(
                    win, text=text, justify="left", wraplength=360,
                    background=BG_INPUT, foreground=FG_TEXT,
                    relief="solid", borderwidth=1, padx=9, pady=7,
                    font=("Segoe UI", 9))
                label.pack()
                state["window"] = win
                self.__dict__.setdefault("_tooltip_windows", set()).add(win)
            except tk.TclError:
                hide()

        widget.bind("<Enter>", show, add="+")
        widget.bind("<Leave>", hide, add="+")
        widget.bind("<Button-1>", hide, add="+")
        widget.bind("<Unmap>", hide, add="+")
        widget.bind("<Destroy>", hide, add="+")

    def _image_checkbutton(self, parent, variable, text, command=None):
        """A checkbox drawn from the same images as the package picker.

        The themed ttk indicator does not match them, so two different-looking
        checkboxes appeared in the same application.

        ``command`` mirrors ttk.Checkbutton's: it runs after the variable flips,
        and only for an operator click, not for a programmatic ``variable.set``.
        """
        off, on = self._checkbox_images()
        row = tk.Frame(parent, background=BG_PANEL, cursor="hand2")
        row.pack(anchor="w", fill="x")
        box = tk.Label(row, image=on if variable.get() else off, background=BG_PANEL)
        box.pack(side="left")
        label = tk.Label(row, text="  " + text, background=BG_PANEL, foreground=FG_TEXT,
                         font=("Segoe UI", 10), anchor="w", justify="left")
        label.pack(side="left", fill="x", expand=True)

        enabled_state = {"enabled": True}

        def toggle(_event=None):
            if enabled_state["enabled"]:
                variable.set(not variable.get())
                if command is not None:
                    command()

        def paint(*_a):
            box.configure(image=on if variable.get() else off)

        def set_enabled(enabled=True):
            enabled_state["enabled"] = bool(enabled)
            cursor = "hand2" if enabled else "arrow"
            colour = FG_TEXT if enabled else FG_DIM
            row.configure(cursor=cursor)
            label.configure(foreground=colour)
            box.configure(cursor=cursor)
            label.configure(cursor=cursor)

        for widget in (row, box, label):
            widget.bind("<Button-1>", toggle)
        variable.trace_add("write", paint)
        row._feather_set_enabled = set_enabled
        # A tk.Frame has no -state, and _lock_operation_controls *unregisters*
        # any widget whose configure(state=...) raises rather than ignoring it.
        # Without this shim a registered drawn checkbox would silently drop out
        # of the lock set on the first operation and stay clickable mid-build.
        row._feather_state = lambda: "normal" if enabled_state["enabled"] else "disabled"
        paint(); set_enabled(True)
        return row

    def _segmented(self, parent, variable, options):
        """A small segmented control built from classic tk widgets.

        Drawn rather than themed because ttk indicator widgets ignore the dark
        palette on some platforms and become unreadable when hovered.
        """
        bar = tk.Frame(parent, background=LINE, highlightthickness=0, bd=0)
        bar.pack(anchor="w")
        cells = {}

        def paint():
            current = variable.get()
            for value, cell in cells.items():
                active = value == current
                cell.configure(background=ACCENT if active else BG_INPUT,
                               foreground=ACCENT_TEXT if active else FG_TEXT,
                               font=("Segoe UI Semibold", 9) if active else ("Segoe UI", 9))

        for index, (value, label) in enumerate(options):
            cell = tk.Label(bar, text=f"  {label}  ", padx=10, pady=6, cursor="hand2",
                            background=BG_INPUT, foreground=FG_TEXT, font=("Segoe UI", 9))
            cell.grid(row=0, column=index, padx=(0 if index == 0 else 1, 0), sticky="nsew")
            cells[value] = cell

            def choose(_event=None, v=value):
                variable.set(v)
                paint()

            def hover(_event=None, c=cell, v=value):
                if variable.get() != v:
                    c.configure(background=BG_RAIL_ACTIVE)

            def leave(_event=None, v=value):
                paint()

            cell.bind("<Button-1>", choose)
            cell.bind("<Enter>", hover)
            cell.bind("<Leave>", leave)
        paint()
        variable.trace_add("write", lambda *_a: paint())
        return bar

    def _panel_hint(self, parent, text, pady=(0, 0)):
        ttk.Label(parent, text=text, style="PanelHint.TLabel", wraplength=700).pack(anchor="w", pady=pady)
