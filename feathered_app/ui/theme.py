"""Feathered visual primitives and themed dialogs."""

from feathered_app.context import (
    ACCENT,
    ACCENT_DIM,
    APP_TITLE,
    BG_HEADER,
    BG_PANEL,
    ERR_FG,
    FG_DIM,
    FG_TEXT,
    INK_FAINT,
    LINE,
    Optional,
    WARN_FG,
    math,
    tk,
    ttk,
)
from feathered_app.context import _native_messagebox

class _ThemedMessageBox:
    """Dark, application-modal replacement for Tk's native message boxes.

    Native message boxes ignore ttk/application theming on several platforms,
    which makes an ordinary validation error look like a process crash. Keep
    the familiar messagebox API so existing call sites and tests remain simple,
    but render the dialog inside Feathered whenever a live App root exists.
    """

    def __init__(self, native):
        self._native = native
        self._root = None

    def bind_root(self, root) -> None:
        self._root = root

    def _fallback(self, method: str, title, message, **kwargs):
        return getattr(self._native, method)(title, message, **kwargs)

    def _dialog(self, title, message, *, kind="info", buttons=("ok",), default="ok", parent=None, button_labels=None):
        root = parent or self._root
        try:
            if root is None or not root.winfo_exists():
                raise tk.TclError("no live Feathered root")
            win = tk.Toplevel(root)
            win.withdraw()
            win.title(str(title or APP_TITLE))
            win.configure(background=BG_PANEL)
            win.resizable(False, False)
            try:
                win.transient(root.winfo_toplevel())
            except tk.TclError:
                pass

            shell = tk.Frame(win, background=BG_PANEL, highlightthickness=1,
                             highlightbackground=LINE)
            shell.pack(fill="both", expand=True)
            header = tk.Frame(shell, background=BG_HEADER)
            header.pack(fill="x")
            accent = {"error": ERR_FG, "warning": WARN_FG, "question": ACCENT,
                      "info": ACCENT}.get(kind, ACCENT)
            glyph = {"error": "×", "warning": "!", "question": "?", "info": "i"}.get(kind, "i")
            tk.Label(header, text=glyph, background=BG_HEADER, foreground=accent,
                     font=("Segoe UI Semibold", 15), width=2).pack(side="left", padx=(14, 7), pady=11)
            tk.Label(header, text=str(title or APP_TITLE), background=BG_HEADER,
                     foreground=FG_TEXT, font=("Segoe UI Semibold", 10),
                     anchor="w").pack(side="left", fill="x", expand=True, padx=(0, 18), pady=11)

            body = tk.Frame(shell, background=BG_PANEL)
            body.pack(fill="both", expand=True, padx=20, pady=(18, 16))
            msg = tk.Label(body, text=str(message), background=BG_PANEL, foreground=FG_TEXT,
                           font=("Segoe UI", 10), justify="left", anchor="w",
                           wraplength=540)
            msg.pack(fill="x")
            actions = ttk.Frame(body, style="Panel.TFrame")
            actions.pack(fill="x", pady=(20, 0))

            result = {"value": None}
            labels = {"ok": "OK", "yes": "Yes", "no": "No", "cancel": "Cancel",
                      "retry": "Retry"}
            labels.update(button_labels or {})

            def choose(value):
                result["value"] = value
                try:
                    win.grab_release()
                except tk.TclError:
                    pass
                win.destroy()

            for value in reversed(tuple(buttons)):
                style = "Primary.TButton" if value == default else "TButton"
                ttk.Button(actions, text=labels.get(value, value.title()), style=style,
                           command=lambda v=value: choose(v)).pack(side="right", padx=(8, 0))

            escape_value = "cancel" if "cancel" in buttons else ("no" if "no" in buttons else default)
            win.protocol("WM_DELETE_WINDOW", lambda: choose(escape_value))
            win.bind("<Escape>", lambda _e: choose(escape_value))
            win.bind("<Return>", lambda _e: choose(default))
            win.update_idletasks()
            try:
                owner = root.winfo_toplevel()
                x = owner.winfo_rootx() + max(24, (owner.winfo_width() - win.winfo_reqwidth()) // 2)
                y = owner.winfo_rooty() + max(24, (owner.winfo_height() - win.winfo_reqheight()) // 3)
                win.geometry(f"+{x}+{y}")
            except tk.TclError:
                pass
            win.deiconify()
            win.lift()
            win.grab_set()
            try:
                win.focus_force()
            except tk.TclError:
                pass
            root.wait_window(win)
            return result["value"] or escape_value
        except tk.TclError:
            # Headless/unit-test contexts still have the standard API available.
            method = {
                ("ok",): "showinfo" if kind == "info" else "showwarning" if kind == "warning" else "showerror",
                ("yes", "no"): "askyesno",
            }.get(tuple(buttons))
            if method:
                return self._fallback(method, title, message, parent=parent) if parent else self._fallback(method, title, message)
            return default

    def showerror(self, title, message, **kwargs):
        self._dialog(title, message, kind="error", buttons=("ok",), default="ok", parent=kwargs.get("parent"))
        return "ok"

    def showwarning(self, title, message, **kwargs):
        self._dialog(title, message, kind="warning", buttons=("ok",), default="ok", parent=kwargs.get("parent"))
        return "ok"

    def showinfo(self, title, message, **kwargs):
        self._dialog(title, message, kind="info", buttons=("ok",), default="ok", parent=kwargs.get("parent"))
        return "ok"

    def askyesno(self, title, message, **kwargs):
        return self._dialog(title, message, kind="question", buttons=("yes", "no"),
                            default="yes" if kwargs.get("default") == "yes" else "no",
                            parent=kwargs.get("parent")) == "yes"

    def askquestion(self, title, message, **kwargs):
        return self._dialog(title, message, kind="question", buttons=("yes", "no"),
                            default="yes" if kwargs.get("default") == "yes" else "no",
                            parent=kwargs.get("parent"))

    def askokcancel(self, title, message, **kwargs):
        return self._dialog(title, message, kind="question", buttons=("ok", "cancel"),
                            default="ok", parent=kwargs.get("parent")) == "ok"

    def askretrycancel(self, title, message, **kwargs):
        return self._dialog(title, message, kind="question", buttons=("retry", "cancel"),
                            default="retry", parent=kwargs.get("parent")) == "retry"

    def askchoice(self, title, message, choices, *, default=None, kind="warning", parent=None):
        """Show a themed policy/recovery choice using explicit application labels.

        ``choices`` is an ordered sequence of ``(value, label)`` pairs. This is
        intentionally separate from yes/no: recovery decisions should state the
        action they will take instead of forcing the operator to decode Yes/No.
        """
        pairs = [(str(value), str(label)) for value, label in choices]
        if not pairs:
            raise ValueError("askchoice requires at least one choice")
        values = tuple(value for value, _label in pairs)
        labels = {value: label for value, label in pairs}
        selected_default = default if default in values else values[0]
        return self._dialog(title, message, kind=kind, buttons=values, default=selected_default,
                            parent=parent, button_labels=labels)


messagebox = _ThemedMessageBox(_native_messagebox)


def human_size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"



def draw_feather(canvas, x: float, y: float, scale: float = 1.0, quill: str = ACCENT,
                 vane: str = ACCENT_DIM, barbs: Optional[str] = None, tilt: float = -1.32) -> None:
    """Draw a feather mark onto a canvas.

    Vector-drawn rather than shipped as an image: crisp at any size, adds no
    asset files to the PyInstaller bundle, and recolourable per context.

    The silhouette is built from the barbs themselves rather than from a filled
    outline. Barbs sweep *backward* toward the tip at a shallow angle along a
    gently curved rachis, and the two sides are deliberately unequal. A
    symmetric outline with barbs sticking out perpendicular reads as a leaf;
    the sweep and the asymmetry are what make it read as a feather.
    """
    barbs = barbs or quill

    def place(px: float, py: float):
        c, s_ = math.cos(tilt), math.sin(tilt)
        return (x + (px * c - py * s_) * scale, y + (px * s_ + py * c) * scale)

    # Rachis runs from calamus (-40) to tip (+40) with a slight curve.
    def shaft(f: float):
        """Point on the rachis; f=0 at the calamus, 1 at the tip."""
        along = -40 + 80 * f
        curve = -5.0 * math.sin(math.pi * f) * f
        return along, curve

    def envelope(f: float) -> float:
        """Half-width of the vane along the shaft."""
        if f <= 0.24:
            return 0.0
        g = (f - 0.24) / 0.76
        # Peak half-width around a quarter of the shaft: thick enough to read
        # as a feather at small sizes without becoming a leaf.
        return 19.5 * (g ** 0.38) * ((1.0 - g) ** 0.85)

    # Soft vane fill sitting under the barbs, one lobe per side.
    for side, spread in ((1, 1.0), (-1, 0.78)):
        pts = []
        for t in range(26, 101, 3):
            f = t / 100.0
            ax, ay = shaft(f)
            pts.extend(place(ax, ay + side * envelope(f) * spread))
        for t in range(100, 25, -3):
            f = t / 100.0
            ax, ay = shaft(f)
            pts.extend(place(ax, ay))
        canvas.create_polygon(pts, fill=vane, outline="", smooth=True)

    # Barbs, swept toward the tip. Narrower side gets fewer, shorter strokes.
    for side, spread in ((1, 1.0), (-1, 0.78)):
        count = 40
        for i in range(count):
            f = 0.26 + (i / (count - 1.0)) * 0.73
            w = envelope(f) * spread
            if w < 0.5:
                continue
            ax, ay = shaft(f)
            # Sweep: the barb tip sits further along the shaft than its root.
            reach = 0.13 * (1.0 - f) + 0.06
            bx, by = shaft(min(1.0, f + reach))
            x1, y1 = place(ax, ay)
            x2, y2 = place(bx, by + side * w)
            canvas.create_line(x1, y1, x2, y2, fill=barbs,
                               width=max(1, 1.45 * scale), capstyle="round")

    # Rachis over the vane, tapering into a bare calamus below it.
    pts = []
    for t in range(26, 101, 4):
        f = t / 100.0
        ax, ay = shaft(f)
        pts.extend(place(ax, ay))
    canvas.create_line(pts, fill=quill, width=max(1, 2.4 * scale),
                       capstyle="round", smooth=True)
    b0 = place(*shaft(0.0))
    b1 = place(*shaft(0.28))
    canvas.create_line(b0[0], b0[1], b1[0], b1[1], fill=quill,
                       width=max(1, 3.4 * scale), capstyle="round")


class FeatheredActivityPulse(tk.Canvas):
    """Low-cost operation rail: a smooth comet gliding on a thin track.

    The tail is rendered as many tiny rounded line slices rather than blocky
    rectangles. Rounded caps let neighbouring slices visually melt together,
    which keeps the wedge smooth through reversals and removes the jagged edge
    that a dense stack of hard rectangles can leave behind. Every item is
    created once in __init__; frames only move/recolour or adjust line width,
    so a UI-thread stall still stops the motion naturally. Waiting and failed
    states gather the comet into one soft static bar (muted amber / red)."""

    SLICES = 48          # extra density smooths the taper and reversals
    SLICE_W = 0.95       # very short slices blend into one continuous wedge

    @staticmethod
    def _blend(fg: str, bg: str, t: float) -> str:
        t = max(0.0, min(1.0, t))
        f = [int(fg[i:i + 2], 16) for i in (1, 3, 5)]
        b = [int(bg[i:i + 2], 16) for i in (1, 3, 5)]
        return "#%02X%02X%02X" % tuple(round(fv + (bv - fv) * t) for fv, bv in zip(f, b))

    def __init__(self, parent, *, width=42, height=14, bg=BG_HEADER, compact=False, **kw):
        super().__init__(parent, width=width, height=height, background=bg,
                         highlightthickness=0, bd=0, **kw)
        self._indicator_width = int(width)
        self._indicator_height = int(height)
        self._compact = bool(compact)
        self._track_left = 2
        self._track_right = self._indicator_width - 2
        self._bg = bg
        cy = self._indicator_height / 2.0
        thick = 0.9 if compact else 1.05
        self._thickness = thick
        self._track = self.create_rectangle(
            self._track_left, cy - thick, self._track_right, cy + thick,
            fill=INK_FAINT, outline="", tags="activity-static")
        # Precomputed per-slice fade and half-height taper. Cubic ease-out on
        # colour keeps the near-head slices bright; the height curve is gentler
        # so the wedge thins without pinching.
        self._fade = []
        self._taper = []
        for index in range(self.SLICES):
            u = (index + 1) / float(self.SLICES)
            self._fade.append(self._blend(ACCENT, bg, 1.0 - (1.0 - u) ** 3))
            self._taper.append(max(0.30, thick * (1.0 - u ** 1.35)))
        self._slices = [
            self.create_line(0, cy, 0, cy, fill=colour,
                             width=max(1.0, thick * 1.8), capstyle="round",
                             state="hidden", tags="activity-trail")
            for colour in self._fade]
        self._segment = self.create_rectangle(
            self._track_left, cy - thick - 0.55, self._track_left + 7, cy + thick + 0.55,
            fill=ACCENT, outline="", state="hidden", tags="activity-segment")
        self._shown_state = "idle"
        self._last_direction = 1

    @staticmethod
    def _position(frame: float, travel: float) -> float:
        """Ping-pong position in [0, travel]; accepts fractional frames.

        Fractional evaluation lets the tail be sampled along the head's own
        past path rather than assumed to be a straight line behind it."""
        if travel <= 0:
            return 0.0
        period = 24.0
        step = float(frame) % period
        half = period / 2.0
        unit = step / half if step <= half else (period - step) / half
        return max(0.0, min(1.0, unit)) * travel

    @classmethod
    def _velocity(cls, frame: int, travel: float):
        """Signed speed from the actual position curve.

        Direction is derived from movement rather than assumed from the frame
        parity, and the magnitude drives tail length so the wedge retracts
        into the head as it decelerates into a turn instead of snapping to
        the opposite side at full length."""
        here = cls._position(frame, travel)
        prev = cls._position(frame - 1, travel)
        delta = here - prev
        direction = 1 if delta > 0 else (-1 if delta < 0 else 0)
        step = travel / 12.0 if travel else 0.0
        speed = min(1.0, abs(delta) / step) if step else 0.0
        return direction, speed

    def render_frame(self, frame: int, *, active: bool = True, state: str | None = None) -> None:
        state = state or ("active" if active else "idle")
        head_width = 5 if self._compact else 6.5
        cy = self._indicator_height / 2.0
        thickness = self._thickness

        if state == "idle":
            self.itemconfigure(self._segment, state="hidden")
            self.itemconfigure("activity-trail", state="hidden")
            self.itemconfigure(self._track, fill=INK_FAINT)
            self._shown_state = "idle"
            return

        if state != "active":
            colour = WARN_FG if state == "waiting" else ERR_FG
            self.itemconfigure("activity-trail", state="hidden")
            self.itemconfigure(self._segment, state="normal", fill=colour)
            self.itemconfigure(self._track, fill=FG_DIM)
            width = head_width + self.SLICES * self.SLICE_W * 0.45
            x = self._track_left + (self._track_right - self._track_left - width) / 2.0
            self.coords(self._segment, x, cy - thickness - 0.55,
                        x + width, cy + thickness + 0.55)
            self._shown_state = state
            return

        if self._shown_state != "active":
            self.itemconfigure(self._segment, state="normal", fill=ACCENT)
            self.itemconfigure(self._track, fill=FG_DIM)
            for item, colour in zip(self._slices, self._fade):
                self.itemconfigure(item, fill=colour)
            self._shown_state = "active"

        travel = max(0.0, self._track_right - self._track_left - head_width)
        x = self._track_left + self._position(frame, travel)
        self.coords(self._segment, x, cy - thickness - 0.55,
                    x + head_width, cy + thickness + 0.55)

        # The tail samples the head's OWN PAST PATH rather than a straight line
        # behind it. One frame of travel is travel/12 pixels, so stepping back
        # SLICE_W/that many frames per slice spaces them evenly along the path.
        # At a turn the samples fold back over the ground just covered, so the
        # taper stays intact through the reversal instead of running out.
        per_frame = (travel / 12.0) if travel else 0.0
        back_step = (self.SLICE_W / per_frame) if per_frame else 0.0
        for index, item in enumerate(self._slices):
            if back_step <= 0:
                self.itemconfigure(item, state="hidden")
                continue
            past = self._track_left + self._position(frame - (index + 1) * back_step, travel)
            centre = past + head_width / 2.0
            left = max(centre - self.SLICE_W / 2.0, self._track_left)
            right = min(centre + self.SLICE_W / 2.0, self._track_right)
            span = right - left
            if span <= 0.05:
                self.itemconfigure(item, state="hidden")
                continue
            fraction = (index + 1) / float(self.SLICES)
            taper = max(0.30, thickness * (1.0 - fraction ** 1.18))
            width = max(1.0, (taper * 2.0) * max(0.35, min(1.0, span / self.SLICE_W)))
            self.itemconfigure(item, state="normal", fill=self._fade[index], width=width)
            self.coords(item, left, cy, right, cy)


class FeatheredMark(tk.Canvas):
    """The product mark as a reusable widget."""

    def __init__(self, parent, size: int = 44, bg: str = BG_HEADER, scale: float = 0.62, **kw):
        super().__init__(parent, width=size, height=size, background=bg,
                         highlightthickness=0, bd=0, **kw)
        # Light rachis against the dark header, with barbs a shade brighter than
        # the vane so the texture survives at small sizes.
        #
        # The feather geometry spans roughly 42 units of radius from its centre
        # (shaft half-length 40 plus curve/stroke width); rotation preserves
        # that radius, so any effective scale above (size/2 - margin)/42 chops
        # the tip at the canvas edge. Clamp to the largest scale that fits.
        requested = scale * (size / 44.0)
        fit = (size / 2.0 - 1.5) / 42.0
        draw_feather(self, size / 2, size / 2, scale=min(requested, fit),
                     quill="#EDF2F7", vane=ACCENT_DIM, barbs=ACCENT)
