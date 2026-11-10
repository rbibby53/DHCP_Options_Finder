#!/usr/bin/env python3
"""DHCP Options Finder GUI: Tkinter front end (Linux, macOS, Windows)."""
import os
import queue
import shlex
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .baseline import compare, load_baseline
from .net import ProbeError, default_interface, is_admin, list_interfaces, parse_codes, parse_mac, probe
from .report import format_json, format_text, summarize, to_record

APP = "DHCP Options Finder"

VENDOR_CLASSES = ["", "PXEClient", "MSFT 5.0", "OptiIpPhone", "Cisco AP c9130", "ubnt", "ArubaAP"]
COLORS = {"warn": "#b26a00", "info": "#1f5fa8", "ok": "#2e7d32", "change": "#6a1b9a"}


# ---------------------------------------------------------------- elevation

def _relaunch_argv():
    """argv that starts this app again: the frozen executable, or python + the launcher script.

    The launcher is whatever started us: dhcpprobe_gui.py in a checkout, or the
    `dhcp-options-finder` script pipx installed. Fall back to `-m` if neither is a file.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable]
    launcher = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if os.path.isfile(launcher) and not launcher.endswith(("pytest", "py.test", "__main__.py")):
        return [sys.executable, launcher]
    return [sys.executable, "-m", "dhcp_options_finder.gui"]


def relaunch_elevated():
    """Start a new elevated copy. Returns a Popen to wait on (macOS), True (Windows), or raises."""
    argv = _relaunch_argv()
    if os.name == "nt":
        import ctypes
        exe = argv[0]
        if exe.lower().endswith("python.exe"):  # no console window for the GUI
            exe = exe[:-10] + "pythonw.exe"
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe,
                                                 subprocess.list2cmdline(argv[1:]), None, 1)
        if rc <= 32:  # user cancelled UAC or launch failed
            raise OSError(f"Windows didn't start the elevated copy (code {rc}).")
        return True
    if sys.platform == "darwin":
        cmd = " ".join(shlex.quote(a) for a in argv) + " >/dev/null 2>&1 &"
        script = cmd.replace("\\", "\\\\").replace('"', '\\"')
        return subprocess.Popen(["osascript", "-e",
                                 f'do shell script "{script}" with administrator privileges'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    raise OSError("Automatic relaunch isn't supported on this platform.")


def _describe_change(c):
    name = f"{c['name']} ({c['option']})" if c["option"] is not None else c["name"]
    if c["kind"] == "added":
        return f"Since baseline: {name} is new: {c['now']}"
    if c["kind"] == "removed":
        return f"Since baseline: {name} was removed (was {c['was']})"
    return f"Since baseline: {name} changed from {c['was']} to {c['now']}"


def sudo_hint():
    return "sudo -E " + " ".join(shlex.quote(a) for a in _relaunch_argv())


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP} {__version__}")
        self._set_icon()
        self.geometry("980x700")
        self.minsize(760, 520)
        self.replies = []
        self.baseline = None
        self.baseline_name = ""
        self.q = queue.Queue()
        self.ifaces = []
        self._style()
        self._build()
        self.refresh_ifaces()
        self._priv_check()

    def _set_icon(self):
        try:
            self._icon = tk.PhotoImage(file=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                         "assets", "icon.png"))
            self.iconphoto(True, self._icon)
        except tk.TclError:
            pass  # icon is cosmetic

    # ------------------------------------------------------------ layout
    def _style(self):
        st = ttk.Style(self)
        if sys.platform.startswith("linux") and "clam" in st.theme_names():
            st.theme_use("clam")
        st.configure("Treeview", rowheight=22)
        st.configure("Warn.TLabel", foreground="#b00020")
        st.configure("Hint.TLabel", foreground="#666666")

    def _build(self):
        pad = {"padx": 6, "pady": 4}
        cfg = ttk.LabelFrame(self, text="Query")
        cfg.pack(fill="x", padx=10, pady=(10, 4))
        for c in (1, 4):
            cfg.columnconfigure(c, weight=1)

        ttk.Label(cfg, text="Interface").grid(row=0, column=0, sticky="w", **pad)
        self.iface_var = tk.StringVar()
        self.iface_cb = ttk.Combobox(cfg, textvariable=self.iface_var, state="readonly")
        self.iface_cb.grid(row=0, column=1, columnspan=4, sticky="ew", **pad)
        ttk.Button(cfg, text="Refresh", command=self.refresh_ifaces).grid(row=0, column=5, **pad)

        ttk.Label(cfg, text="Mode").grid(row=1, column=0, sticky="w", **pad)
        mf = ttk.Frame(cfg)
        mf.grid(row=1, column=1, sticky="w", **pad)
        self.mode = tk.StringVar(value="discover")
        ttk.Radiobutton(mf, text="Discover (new client)", value="discover",
                        variable=self.mode).pack(side="left")
        ttk.Radiobutton(mf, text="Inform (host has IP)", value="inform",
                        variable=self.mode).pack(side="left", padx=(10, 0))
        ttk.Label(cfg, text="Timeout (s)").grid(row=1, column=3, sticky="e", **pad)
        self.timeout = tk.StringVar(value="5")
        ttk.Spinbox(cfg, from_=1, to=60, width=6, textvariable=self.timeout).grid(
            row=1, column=4, sticky="w", **pad)
        self.first = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text="Stop at first reply", variable=self.first).grid(
            row=1, column=5, sticky="w", **pad)

        ttk.Label(cfg, text="Client MAC").grid(row=2, column=0, sticky="w", **pad)
        macf = ttk.Frame(cfg)
        macf.grid(row=2, column=1, sticky="ew", **pad)
        self.mac = tk.StringVar()
        ttk.Entry(macf, textvariable=self.mac).pack(side="left", fill="x", expand=True)
        self.use_iface_mac = tk.BooleanVar(value=False)
        ttk.Checkbutton(macf, text="Use this computer's MAC", variable=self.use_iface_mac).pack(
            side="left", padx=(6, 0))
        ttk.Label(cfg, text="Vendor class (60)").grid(row=2, column=3, sticky="e", **pad)
        self.vclass = tk.StringVar()
        ttk.Combobox(cfg, textvariable=self.vclass, values=VENDOR_CLASSES).grid(
            row=2, column=4, columnspan=2, sticky="ew", **pad)

        ttk.Label(cfg, text="Hostname (12)").grid(row=3, column=0, sticky="w", **pad)
        self.hostname = tk.StringVar()
        ttk.Entry(cfg, textvariable=self.hostname).grid(row=3, column=1, sticky="ew", **pad)
        ttk.Label(cfg, text="Unicast to server").grid(row=3, column=3, sticky="e", **pad)
        self.server = tk.StringVar()
        ttk.Entry(cfg, textvariable=self.server).grid(row=3, column=4, columnspan=2,
                                                      sticky="ew", **pad)

        ttk.Label(cfg, text="Request options").grid(row=4, column=0, sticky="w", **pad)
        self.req = tk.StringVar(value="1-254")
        ttk.Entry(cfg, textvariable=self.req).grid(row=4, column=1, sticky="ew", **pad)
        ttk.Label(cfg, text="Blank MAC: random for Discover. Blank server: broadcast.",
                  style="Hint.TLabel").grid(row=4, column=3, columnspan=3, sticky="w", **pad)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=4)
        self.run_btn = ttk.Button(bar, text="Run Probe", command=self.run)
        self.run_btn.pack(side="left")
        self.prog = ttk.Progressbar(bar, mode="indeterminate", length=120)
        self.prog.pack(side="left", padx=8)
        self.status = tk.StringVar(value="Ready.")
        ttk.Label(bar, textvariable=self.status).pack(side="left", fill="x", expand=True)
        self.show_raw = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Show raw hex", variable=self.show_raw,
                        command=self._toggle_raw).pack(side="right")

        self.warn = tk.StringVar()
        ttk.Label(self, textvariable=self.warn, style="Warn.TLabel").pack(fill="x", padx=12)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=4)
        self._placeholder()

        bot = ttk.Frame(self)
        bot.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bot, text="Copy as Text", command=self.copy_text).pack(side="left")
        ttk.Button(bot, text="Save Text…", command=lambda: self.save("txt")).pack(
            side="left", padx=4)
        ttk.Button(bot, text="Save JSON…", command=lambda: self.save("json")).pack(side="left")
        self.base_btn = ttk.Button(bot, text="Compare to Baseline…", command=self.toggle_baseline)
        self.base_btn.pack(side="left", padx=(12, 0))
        self.base_lbl = tk.StringVar()
        ttk.Label(bot, textvariable=self.base_lbl, style="Hint.TLabel").pack(side="left", padx=6)
        ttk.Label(bot, text="Double-click a row for the full value.",
                  style="Hint.TLabel").pack(side="right")

        self.bind("<Return>", lambda e: self.run())

    def _placeholder(self):
        for t in self.nb.tabs():
            self.nb.forget(t)
        f = ttk.Frame(self.nb)
        ttk.Label(f, text="Run a probe to see what the DHCP server hands out.",
                  style="Hint.TLabel").pack(expand=True)
        self.nb.add(f, text="Results")
        self.trees = []

    # ------------------------------------------------------------ interfaces
    def refresh_ifaces(self):
        try:
            self.ifaces = list_interfaces()
            d = default_interface(self.ifaces)
        except ProbeError as e:
            messagebox.showerror(APP, str(e))
            return
        labels = [f"{i['name']}  —  {i['ip'] or 'no IPv4'}  —  {i['mac']}"
                  f"{'' if i['up'] else '  (down)'}" for i in self.ifaces]
        self.iface_cb["values"] = labels
        if labels:
            idx = self.ifaces.index(d) if d in self.ifaces else 0
            self.iface_cb.current(idx)

    def _priv_check(self):
        if is_admin():
            return
        if sys.platform.startswith("linux"):
            self.warn.set(f"Not running as root, so probes will fail. Close this and run: {sudo_hint()}")

    # ------------------------------------------------------------ probe
    def run(self):
        if str(self.run_btn["state"]) == "disabled":
            return
        sel = self.iface_cb.current()
        if sel < 0:
            messagebox.showerror(APP, "Pick an interface.")
            return
        try:
            kw = dict(
                iface=self.ifaces[sel], mode=self.mode.get(),
                mac=parse_mac(self.mac.get().strip()) if self.mac.get().strip() else None,
                use_iface_mac=self.use_iface_mac.get(),
                vendor_class=self.vclass.get().strip() or None,
                hostname=self.hostname.get().strip() or None,
                request=parse_codes(self.req.get()) or list(range(1, 255)),
                server=self.server.get().strip() or None,
                timeout=float(self.timeout.get()), first=self.first.get(),
                log=lambda m: self.q.put(("log", m)))
        except ValueError as e:
            messagebox.showerror(APP, f"Bad input: {e}")
            return
        self.run_btn.state(["disabled"])
        self.prog.start(12)
        self.warn.set("")
        self._priv_check()
        threading.Thread(target=self._worker, args=(kw,), daemon=True).start()
        self.after(100, self._poll)

    def _worker(self, kw):
        try:
            self.q.put(("done", probe(**kw)))
        except ProbeError as e:
            self.q.put(("error", (str(e), e.permission)))
        except Exception as e:  # surface anything unexpected instead of hanging
            self.q.put(("error", (f"{type(e).__name__}: {e}", False)))

    def _poll(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "log":
                    self.status.set(val)
                    continue
                self.prog.stop()
                self.run_btn.state(["!disabled"])
                if kind == "error":
                    self.status.set("Failed.")
                    msg, permission = val
                    if permission:
                        self.offer_elevation(msg)
                    else:
                        messagebox.showerror(APP, msg)
                else:
                    self.show(val)
                return
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # ------------------------------------------------------------ results
    def show(self, replies):
        self.replies = replies
        self._placeholder()
        if not replies:
            self.status.set("No replies.")
            self.nb.forget(self.nb.tabs()[0])
            f = ttk.Frame(self.nb)
            ttk.Label(f, text=format_text([]), wraplength=700,
                      style="Hint.TLabel").pack(expand=True)
            self.nb.add(f, text="No replies")
            return
        self.nb.forget(self.nb.tabs()[0])
        sums = [summarize(p) for p in replies]
        for n, s in enumerate(sums, 1):
            self._add_tab(n, s)
        servers = sorted({s["server_id"] for s in sums} - {None})
        self.status.set(f"{len(replies)} repl{'y' if len(replies) == 1 else 'ies'} "
                        f"from {len(servers) or 1} server(s).")
        if len(servers) > 1:
            self.warn.set(f"Multiple DHCP servers answered: {', '.join(servers)}. "
                          "Check for a rogue server if that isn't expected.")

    def _add_tab(self, n, s):
        f = ttk.Frame(self.nb)
        head = f"DHCP{s['type']} from {s['source']}   Server ID: {s['server_id'] or '-'}"
        ttk.Label(f, text=head, font=("TkDefaultFont", 11, "bold")).pack(
            anchor="w", padx=6, pady=(6, 2))
        changes = []
        if self.baseline is not None and n == 1:
            changes = compare(to_record(self.replies[0]), self.baseline)
        self._findings_panel(f, s["findings"], changes)

        wrap = ttk.Frame(f)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        cols = ("name", "value", "raw")
        tv = ttk.Treeview(wrap, columns=cols, show="tree headings", selectmode="extended")
        tv.heading("#0", text="Code")
        tv.column("#0", width=80, stretch=False)
        tv.heading("name", text="Option")
        tv.column("name", width=250, stretch=False)
        tv.heading("value", text="Value")
        tv.column("value", width=480)
        tv.heading("raw", text="Raw (hex)")
        tv.column("raw", width=260)
        ys = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tv.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        tv.tag_configure("hdr", foreground="#555555")
        tv.tag_configure("changed", background="#fff3c4")
        tv.tag_configure("added", background="#dff3e1")
        tv.tag_configure("removed", foreground="#888888")
        kinds = {c["option"]: c["kind"] for c in changes if c["option"] is not None}

        if s["header"]:
            for label, v in s["header"]:
                tv.insert("", "end", text="BOOTP", values=(label, v, ""), tags=("hdr",))
        for o in s["options"]:
            tag = (kinds[o["code"]],) if o["code"] in kinds else ()
            iid = tv.insert("", "end", text=str(o["code"]),
                            values=(o["name"], o["values"][0], o["raw"]), open=True, tags=tag)
            for extra in o["values"][1:]:
                if extra.startswith("raw: 0x"):
                    continue  # already in the Raw (hex) column
                tv.insert(iid, "end", text="", values=("", extra, ""), tags=tag)
        for c in changes:
            if c["kind"] == "removed":
                tv.insert("", "end", text=str(c["option"]),
                          values=(c["name"], f"(removed; was {c['was']})", ""), tags=("removed",))

        tv.bind("<Double-1>", lambda e, t=tv: self._detail(t))
        mod = "Command" if sys.platform == "darwin" else "Control"
        tv.bind(f"<{mod}-c>", lambda e, t=tv: self._copy_rows(t))
        self.trees.append(tv)
        self._apply_raw(tv)
        self.nb.add(f, text=f"{n}: {s['source']} ({s['type']})")

    def _findings_panel(self, parent, findings, changes):
        box = ttk.Frame(parent)
        box.pack(fill="x", padx=8, pady=(0, 2))
        rows = [("warn" if f["level"] == "warn" else "info", f["message"]) for f in findings]
        if self.baseline is not None and changes is not None:
            if changes:
                rows += [("change", _describe_change(c)) for c in changes]
            else:
                rows.append(("ok", f"Matches baseline {self.baseline_name}."))
        if not findings:
            rows.insert(0, ("ok", "Checks: no issues found."))
        icons = {"warn": "⚠", "info": "ℹ", "ok": "✓", "change": "Δ"}
        for level, msg in rows:
            line = ttk.Frame(box)
            line.pack(fill="x", anchor="w")
            tk.Label(line, text=icons[level], fg=COLORS[level], width=2).pack(side="left", anchor="n")
            ttk.Label(line, text=msg, wraplength=860, justify="left").pack(side="left", anchor="w")

    def toggle_baseline(self):
        if self.baseline is not None:
            self.baseline, self.baseline_name = None, ""
            self.base_btn.configure(text="Compare to Baseline…")
            self.base_lbl.set("")
        else:
            path = filedialog.askopenfilename(title="Baseline (a saved JSON export)",
                                              filetypes=[("JSON", "*.json"), ("All files", "*")])
            if not path:
                return
            try:
                self.baseline = load_baseline(path)
            except (OSError, ValueError) as e:
                messagebox.showerror(APP, f"Couldn't load baseline: {e}")
                return
            self.baseline_name = os.path.basename(path)
            self.base_btn.configure(text="Stop Comparing")
            self.base_lbl.set(f"Baseline: {self.baseline_name}")
        if self.replies:
            self.show(self.replies)

    def offer_elevation(self, msg):
        if os.name != "nt" and sys.platform != "darwin":
            messagebox.showerror(APP, f"{msg}\n\nClose this window and run:\n\n{sudo_hint()}")
            return
        if not messagebox.askyesno(APP, f"{msg}\n\n{APP} needs administrator rights to use the "
                                        "DHCP client port. Relaunch with administrator rights?"):
            return
        try:
            proc = relaunch_elevated()
        except OSError as e:
            messagebox.showerror(APP, str(e))
            return
        if proc is True:
            self.destroy()
            return
        self.status.set("Waiting for the administrator password…")
        self._wait_elevation(proc)

    def _wait_elevation(self, proc):
        if proc.poll() is None:
            self.after(300, self._wait_elevation, proc)
        elif proc.returncode == 0:
            self.destroy()
        else:
            self.status.set("Relaunch cancelled.")

    def _apply_raw(self, tv):
        tv["displaycolumns"] = ("name", "value", "raw") if self.show_raw.get() else ("name", "value")

    def _toggle_raw(self):
        for tv in self.trees:
            self._apply_raw(tv)

    def _row_text(self, tv, iid):
        code = tv.item(iid, "text")
        name, val, raw = tv.item(iid, "values")
        return "\t".join(x for x in (code, name, val) if x)

    def _copy_rows(self, tv):
        text = "\n".join(self._row_text(tv, i) for i in tv.selection())
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status.set(f"Copied {len(tv.selection())} row(s).")

    def _detail(self, tv):
        iid = tv.focus()
        if not iid:
            return
        parent = tv.parent(iid) or iid
        code = tv.item(parent, "text")
        name, first, raw = tv.item(parent, "values")
        vals = [first] + [tv.item(c, "values")[1] for c in tv.get_children(parent)]
        w = tk.Toplevel(self)
        w.title(f"Option {code}: {name}")
        w.geometry("640x360")
        txt = tk.Text(w, wrap="word", font=("TkFixedFont", 10))
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        body = f"Option {code}  {name}\n\nValue:\n  " + "\n  ".join(vals)
        if raw:
            body += f"\n\nRaw ({len(raw)//2} bytes):\n  {raw}"
        txt.insert("1.0", body)
        txt.configure(state="disabled")

    # ------------------------------------------------------------ export
    def copy_text(self):
        if not self.replies:
            return
        self.clipboard_clear()
        self.clipboard_append(format_text(self.replies, self.show_raw.get(), self.baseline))
        self.status.set("Copied results to clipboard.")

    def save(self, kind):
        if not self.replies:
            messagebox.showinfo(APP, "Nothing to save yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{kind}", initialfile=f"dhcp-options.{kind}",
            filetypes=[("JSON", "*.json")] if kind == "json" else [("Text", "*.txt")])
        if not path:
            return
        data = (format_json(self.replies) if kind == "json"
                else format_text(self.replies, self.show_raw.get(), self.baseline))
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        self.status.set(f"Saved {os.path.basename(path)}")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
