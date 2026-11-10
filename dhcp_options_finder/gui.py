#!/usr/bin/env python3
"""DHCP Options Finder GUI: Tkinter front end (Linux, macOS, Windows)."""
import os
import queue
import shlex
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import __version__, profiles, ra
from . import dhcpv6 as d6
from .baseline import compare, load_baseline
from .net import (
    ProbeError,
    default_interface,
    is_admin,
    list_interfaces,
    parse_codes,
    parse_mac,
    probe,
    sweep,
)
from .net6 import probe6
from .options import VENDOR_CLASS_PRESETS
from .report import (
    format_json,
    format_sweep,
    format_sweep_json,
    format_text,
    summarize,
    sweep_summary,
    to_record,
)
from .report6 import check6, format_json6, format_text6

APP = "DHCP Options Finder"

VENDOR_CLASSES = VENDOR_CLASS_PRESETS
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


def _os():
    """'windows', 'mac' or 'linux'. A function so tests can fake it without touching os/sys."""
    if os.name == "nt":
        return "windows"
    return "mac" if sys.platform == "darwin" else "linux"


def relaunch_elevated():
    """Start a new elevated copy. Returns a Popen to wait on (macOS), True (Windows), or raises."""
    argv = _relaunch_argv()
    kind = _os()
    if kind == "windows":
        import ctypes
        exe = argv[0]
        if exe.lower().endswith("python.exe"):  # no console window for the GUI
            exe = exe[:-10] + "pythonw.exe"
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe,
                                                 subprocess.list2cmdline(argv[1:]), None, 1)
        if rc <= 32:  # user cancelled UAC or launch failed
            raise OSError(f"Windows didn't start the elevated copy (code {rc}).")
        return True
    if kind == "mac":
        env = (f"DHCPOF_CONFIG_DIR={shlex.quote(profiles.config_dir())} "
               f"DHCPOF_OWNER={os.getuid()}:{os.getgid()} ")
        cmd = env + " ".join(shlex.quote(a) for a in argv) + " >/dev/null 2>&1 &"
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


def _sweep_change(c):
    name = f"{c['name']} ({c['option']})" if c["option"] is not None else c["name"]
    if c["kind"] == "added":
        return f"{name}: {c['now']}   (only with this class)"
    if c["kind"] == "removed":
        return f"{name}: not sent   (reference: {c['was']})"
    return f"{name}: {c['now']}   (reference: {c['was']})"


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
        self.sweep_result = None  # (mac, [(vendor_class, replies)]) when the last run was a sweep
        self.v6_result = None     # probe6() result when the last run was IPv6
        self.baseline = None
        self.baseline_name = ""
        self.q = queue.Queue()
        self.ifaces = []
        self._style()
        self._build()
        self.refresh_ifaces()
        self._apply_settings(profiles.last())
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
        pf = ttk.Frame(self)
        pf.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(pf, text="Profile").pack(side="left")
        self.profile_var = tk.StringVar()
        self.profile_cb = ttk.Combobox(pf, textvariable=self.profile_var, state="readonly", width=28)
        self.profile_cb.pack(side="left", padx=6)
        self.profile_cb.bind("<<ComboboxSelected>>", lambda e: self.load_profile())
        ttk.Button(pf, text="Save As…", command=self.save_profile).pack(side="left")
        ttk.Button(pf, text="Delete", command=self.delete_profile).pack(side="left", padx=4)
        ttk.Label(pf, text="Your last settings are restored automatically.",
                  style="Hint.TLabel").pack(side="left", padx=8)
        self._refresh_profiles()

        cfg = ttk.LabelFrame(self, text="Query")
        cfg.pack(fill="x", padx=10, pady=(6, 4))
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
        self.v4_only = []
        for text, val, padx in (("Discover (new client)", "discover", 0),
                                ("Inform (host has IP)", "inform", 10)):
            rb = ttk.Radiobutton(mf, text=text, value=val, variable=self.mode)
            rb.pack(side="left", padx=(padx, 0))
            self.v4_only.append(rb)
        ttk.Label(cfg, text="Timeout (s)").grid(row=1, column=3, sticky="e", **pad)
        self.timeout = tk.StringVar(value="5")
        ttk.Spinbox(cfg, from_=1, to=60, width=6, textvariable=self.timeout).grid(
            row=1, column=4, sticky="w", **pad)
        self.first = tk.BooleanVar(value=False)
        w = ttk.Checkbutton(cfg, text="Stop at first reply", variable=self.first)
        w.grid(row=1, column=5, sticky="w", **pad)
        self.v4_only.append(w)

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
        w = ttk.Combobox(cfg, textvariable=self.vclass, values=VENDOR_CLASSES)
        w.grid(row=2, column=4, columnspan=2, sticky="ew", **pad)
        self.v4_only.append(w)

        ttk.Label(cfg, text="Hostname (12)").grid(row=3, column=0, sticky="w", **pad)
        self.hostname = tk.StringVar()
        w = ttk.Entry(cfg, textvariable=self.hostname)
        w.grid(row=3, column=1, sticky="ew", **pad)
        self.v4_only.append(w)
        ttk.Label(cfg, text="Unicast to server").grid(row=3, column=3, sticky="e", **pad)
        self.server = tk.StringVar()
        ttk.Entry(cfg, textvariable=self.server).grid(row=3, column=4, columnspan=2,
                                                      sticky="ew", **pad)

        ttk.Label(cfg, text="Request options").grid(row=4, column=0, sticky="w", **pad)
        self.req = tk.StringVar(value="1-254")
        w = ttk.Entry(cfg, textvariable=self.req)
        w.grid(row=4, column=1, sticky="ew", **pad)
        self.v4_only.append(w)
        ttk.Label(cfg, text="Blank MAC: random for Discover. Blank server: broadcast.",
                  style="Hint.TLabel").grid(row=4, column=3, columnspan=3, sticky="w", **pad)

        ttk.Label(cfg, text="Protocol").grid(row=5, column=0, sticky="w", **pad)
        pf6 = ttk.Frame(cfg)
        pf6.grid(row=5, column=1, columnspan=5, sticky="w", **pad)
        self.family = tk.StringVar(value="ipv4")
        for text, val in (("IPv4 (DHCP)", "ipv4"), ("IPv6 (RA + DHCPv6)", "ipv6")):
            ttk.Radiobutton(pf6, text=text, value=val, variable=self.family,
                            command=self._family_changed).pack(side="left", padx=(0, 10))
        ttk.Label(cfg, text="IPv6 checks").grid(row=6, column=0, sticky="w", **pad)
        pf6b = ttk.Frame(cfg)
        pf6b.grid(row=6, column=1, columnspan=5, sticky="w", **pad)
        self.v6_ra, self.v6_info = tk.BooleanVar(value=True), tk.BooleanVar(value=True)
        self.v6_solicit, self.v6_pd = tk.BooleanVar(value=True), tk.BooleanVar(value=False)
        self.v6_only = []
        for text, var in (("Router Advertisements", self.v6_ra), ("DHCPv6 options", self.v6_info),
                          ("DHCPv6 address (Solicit)", self.v6_solicit),
                          ("Prefix delegation (IA_PD)", self.v6_pd)):
            cb = ttk.Checkbutton(pf6b, text=text, variable=var)
            cb.pack(side="left", padx=(0, 8))
            self.v6_only.append(cb)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=4)
        self.run_btn = ttk.Button(bar, text="Run Probe", command=self.run)
        self.run_btn.pack(side="left")
        self.sweep_btn = ttk.Button(bar, text="Sweep Vendor Classes", command=self.run_sweep)
        self.sweep_btn.pack(side="left", padx=(6, 0))
        self.v4_only.append(self.sweep_btn)
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
        self.v4_only.append(self.base_btn)
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
    # ------------------------------------------------------------ settings & profiles
    def _settings(self):
        sel = self.iface_cb.current()
        return {"iface": self.ifaces[sel]["name"] if 0 <= sel < len(self.ifaces) else None,
                "mode": self.mode.get(), "mac": self.mac.get().strip(),
                "use_iface_mac": self.use_iface_mac.get(), "vendor_class": self.vclass.get().strip(),
                "hostname": self.hostname.get().strip(), "server": self.server.get().strip(),
                "request": self.req.get().strip(), "timeout": self.timeout.get().strip(),
                "family": self.family.get(), "v6_ra": self.v6_ra.get(), "v6_info": self.v6_info.get(),
                "v6_solicit": self.v6_solicit.get(), "v6_pd": self.v6_pd.get()}

    def _apply_settings(self, st):
        if not st:
            return
        names = [i["name"] for i in self.ifaces]
        if st.get("iface") in names:
            self.iface_cb.current(names.index(st["iface"]))
        if st.get("mode") in ("discover", "inform"):
            self.mode.set(st["mode"])
        self.use_iface_mac.set(bool(st.get("use_iface_mac")))
        for var, key, default in ((self.mac, "mac", ""), (self.vclass, "vendor_class", ""),
                                  (self.hostname, "hostname", ""), (self.server, "server", ""),
                                  (self.req, "request", "1-254"), (self.timeout, "timeout", "5")):
            var.set(str(st.get(key, default)))
        self.family.set(st.get("family", "ipv4") if st.get("family") in ("ipv4", "ipv6") else "ipv4")
        for var, key, default in ((self.v6_ra, "v6_ra", True), (self.v6_info, "v6_info", True),
                                  (self.v6_solicit, "v6_solicit", True), (self.v6_pd, "v6_pd", False)):
            var.set(bool(st.get(key, default)))
        self._family_changed()

    def _family_changed(self):
        v6 = self.family.get() == "ipv6"
        for w in self.v4_only:
            w.state(["disabled"] if v6 else ["!disabled"])
        for w in self.v6_only:
            w.state(["!disabled"] if v6 else ["disabled"])

    def _refresh_profiles(self, select=""):
        self.profile_cb["values"] = profiles.names()
        self.profile_var.set(select)

    def load_profile(self):
        st = profiles.get(self.profile_var.get())
        if st:
            self._apply_settings({"mac": "", "vendor_class": "", "hostname": "", "server": "",
                                  "request": "1-254", "timeout": "5", **st})
            self.status.set(f"Loaded profile {self.profile_var.get()!r}.")

    def save_profile(self):
        name = simpledialog.askstring(APP, "Profile name:", initialvalue=self.profile_var.get(),
                                      parent=self)
        if not name or not name.strip():
            return
        try:
            profiles.put(name.strip(), self._settings())
        except (OSError, ValueError) as e:
            messagebox.showerror(APP, f"Couldn't save profile: {e}")
            return
        self._refresh_profiles(name.strip())
        self.status.set(f"Saved profile {name.strip()!r}.")

    def delete_profile(self):
        name = self.profile_var.get()
        if name and messagebox.askyesno(APP, f"Delete profile {name!r}?"):
            profiles.delete(name)
            self._refresh_profiles()

    # ------------------------------------------------------------ probe
    def _probe_kwargs(self):
        sel = self.iface_cb.current()
        if sel < 0:
            messagebox.showerror(APP, "Pick an interface.")
            return None
        try:
            return dict(
                iface=self.ifaces[sel], mode=self.mode.get(),
                mac=parse_mac(self.mac.get().strip()) if self.mac.get().strip() else None,
                use_iface_mac=self.use_iface_mac.get(),
                hostname=self.hostname.get().strip() or None,
                request=parse_codes(self.req.get()) or list(range(1, 255)),
                server=self.server.get().strip() or None,
                timeout=float(self.timeout.get()))
        except ValueError as e:
            messagebox.showerror(APP, f"Bad input: {e}")
            return None

    def _busy(self):
        return str(self.run_btn["state"]) == "disabled"

    def _start(self, kind, fn, kw):
        profiles.save_last(self._settings())
        for b in (self.run_btn, self.sweep_btn):
            b.state(["disabled"])
        self.prog.start(12)
        self.warn.set("")
        self._priv_check()
        threading.Thread(target=self._worker, args=(kind, fn, kw), daemon=True).start()
        self.after(100, self._poll)

    def run(self):
        if self._busy():
            return
        kw = self._probe_kwargs()
        if kw is None:
            return
        if self.family.get() == "ipv6":
            if not (self.v6_ra.get() or self.v6_info.get() or self.v6_solicit.get()):
                messagebox.showerror(APP, "Tick at least one IPv6 check.")
                return
            self._start("v6", probe6, dict(
                iface=kw["iface"], timeout=kw["timeout"], mac=kw["mac"],
                use_iface_mac=kw["use_iface_mac"], server=kw["server"], ra_on=self.v6_ra.get(),
                info=self.v6_info.get(), solicit=self.v6_solicit.get(), pd=self.v6_pd.get(),
                log=lambda m: self.q.put(("log", m))))
            return
        kw.update(vendor_class=self.vclass.get().strip() or None, first=self.first.get(),
                  log=lambda m: self.q.put(("log", m)))
        self._start("done", probe, kw)

    def run_sweep(self):
        if self._busy():
            return
        kw = self._probe_kwargs()
        if kw is None:
            return
        classes = list(VENDOR_CLASS_PRESETS)
        custom = self.vclass.get().strip()
        if custom and custom not in classes:
            classes.append(custom)
        kw.update(classes=classes, progress=lambda n, total, vc: self.q.put(
            ("log", f"Sweep {n}/{total}: {vc or '(no option 60)'}…")))
        self._start("sweep", lambda classes, **k: sweep(classes, **k), kw)

    def _worker(self, kind, fn, kw):
        try:
            self.q.put((kind, fn(**kw)))
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
                if self.family.get() == "ipv4":
                    self.sweep_btn.state(["!disabled"])
                if kind == "error":
                    self.status.set("Failed.")
                    msg, permission = val
                    if permission:
                        self.offer_elevation(msg)
                    else:
                        messagebox.showerror(APP, msg)
                elif kind == "sweep":
                    self.show_sweep(*val)
                elif kind == "v6":
                    self.show6(val)
                else:
                    self.show(val)
                return
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # ------------------------------------------------------------ results
    def show(self, replies):
        self.replies = replies
        self.sweep_result = self.v6_result = None
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

    def _tree(self, parent, columns, headings, widths):
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        tv = ttk.Treeview(wrap, columns=columns, show="tree headings")
        for col, head, width in zip(("#0", *columns), headings, widths, strict=True):
            tv.heading(col, text=head)
            tv.column(col, width=width, stretch=col == columns[-1])
        ys = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=ys.set)
        tv.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        tv.tag_configure("head", font=("TkDefaultFont", 10, "bold"))
        return tv

    def show6(self, res):
        self.replies, self.sweep_result, self.v6_result = [], None, res
        self._placeholder()
        self.nb.forget(self.nb.tabs()[0])
        findings = check6(res)

        f = ttk.Frame(self.nb)
        ttk.Label(f, text=f"IPv6 on {res['iface']}   link-local {res['link_local']}",
                  font=("TkDefaultFont", 11, "bold")).pack(anchor="w", padx=6, pady=(6, 2))
        if res.get("ra_source") == "windows":
            dns = f" IPv6 DNS in use: {', '.join(res['os_dns'])}." if res.get("os_dns") else ""
            ttk.Label(f, text="Windows doesn't let apps read Router Advertisements; routers below are "
                              f"what Windows learned from them.{dns}",
                      style="Hint.TLabel", wraplength=900).pack(anchor="w", padx=8)
        self._findings_panel(f, findings, None)
        tv = self._tree(f, ("value",), ("Router", "Value"), (300, 640))
        if not res["routers"]:
            why = res["errors"].get("ra") or ("not checked" if not res["ran"]["ra"] else
                                             "no Router Advertisements received")
            tv.insert("", "end", text="(none)", values=(why,))
        for r in res["routers"]:
            default = r["ra"]["router_lifetime"] > 0
            iid = tv.insert("", "end", text=r["source"], open=True, tags=("head",),
                            values=("default router" if default else "not a default router",))
            for label, value in ra.describe(r["ra"]):
                tv.insert(iid, "end", text=label, values=(value,))
        self.nb.add(f, text=f"Routers ({len(res['routers'])})")

        f = ttk.Frame(self.nb)
        tv = self._tree(f, ("name", "value"), ("Code", "Option", "Value"), (80, 260, 600))
        if not res["dhcpv6"]:
            why = res["errors"].get("dhcpv6") or ("not checked" if not res["ran"]["dhcpv6"] else
                                                 "no DHCPv6 server answered")
            tv.insert("", "end", text="", values=("(none)", why))
        for m in res["dhcpv6"]:
            sm = d6.summarize(m)
            pref = f", preference {sm['preference']}" if sm["preference"] is not None else ""
            iid = tv.insert("", "end", text="", open=True, tags=("head",),
                            values=(f"{sm['type']} to {m['request']}", f"from {m['source']}{pref}"))
            for o in sm["options"]:
                oid = tv.insert(iid, "end", text=str(o["code"]), values=(o["name"], o["values"][0]),
                                open=True)
                for extra in o["values"][1:]:
                    tv.insert(oid, "end", text="", values=("", extra))
        self.nb.add(f, text=f"DHCPv6 ({len(res['dhcpv6'])})")
        warns = sum(1 for x in findings if x["level"] == "warn")
        self.status.set(f"{len(res['routers'])} router(s), {len(res['dhcpv6'])} DHCPv6 repl"
                        f"{'y' if len(res['dhcpv6']) == 1 else 'ies'}, {warns} warning(s).")

    def show_sweep(self, mac, results):
        self.replies, self.v6_result = [], None
        self.sweep_result = (mac, results)
        self._placeholder()
        self.nb.forget(self.nb.tabs()[0])
        summary = sweep_summary(results)

        f = ttk.Frame(self.nb)
        ttk.Label(f, text=f"Vendor class sweep: {len(results)} probes, all with client MAC "
                          f"{':'.join(f'{b:02x}' for b in mac)}",
                  font=("TkDefaultFont", 11, "bold")).pack(anchor="w", padx=6, pady=(6, 2))
        ref = summary["reference"]
        ttk.Label(f, text=("No class got a reply." if ref is None else
                           f"Each class is compared with the reply to {ref or 'no option 60'!r}. "
                           "Double-click a class to open its full reply."),
                  style="Hint.TLabel").pack(anchor="w", padx=8)
        wrap = ttk.Frame(f)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        tv = ttk.Treeview(wrap, columns=("result",), show="tree headings")
        tv.heading("#0", text="Vendor class (60)")
        tv.column("#0", width=220, stretch=False)
        tv.heading("result", text="Result")
        tv.column("result", width=700)
        ys = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=ys.set)
        tv.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        tv.tag_configure("differs", background="#fff3c4")
        tv.tag_configure("none", foreground="#888888")
        self.nb.add(f, text="Sweep")

        tabs = {}
        for r in summary["rows"]:
            label = r["vendor_class"] or "(none)"
            if r["status"] == "reference":
                rec = r["replies"][0]
                text = f"Reference: {len(rec['options'])} options from {rec['server_id'] or rec['source']}"
            elif r["status"] == "no reply":
                text = "No reply"
            elif r["status"] == "same":
                text = "Same as reference"
            else:
                n = len(r["changes"])
                text = f"{n} difference{'s' if n != 1 else ''}"
            iid = tv.insert("", "end", text=label, values=(text,), open=True,
                            tags=("differs",) if r["status"] == "differs" else
                            ("none",) if r["status"] == "no reply" else ())
            for c in r["changes"]:
                tv.insert(iid, "end", text="", values=(_sweep_change(c),), tags=("differs",))
            if r["replies"]:
                vc = r["vendor_class"]
                p = next(p for v, rs in results if v == vc for p in rs[:1])
                self._add_tab(0, summarize(p), label=label, use_baseline=False)
                tabs[iid] = self.nb.tabs()[-1]

        def open_tab(_e):
            iid = tv.focus()
            iid = tv.parent(iid) or iid
            if iid in tabs:
                self.nb.select(tabs[iid])
        tv.bind("<Double-1>", open_tab)
        answered = sum(1 for _, rs in results if rs)
        differs = sum(1 for r in summary["rows"] if r["status"] == "differs")
        self.status.set(f"Sweep done: {answered}/{len(results)} classes answered, "
                        f"{differs} got different options.")

    def _add_tab(self, n, s, label=None, use_baseline=True):
        f = ttk.Frame(self.nb)
        head = f"DHCP{s['type']} from {s['source']}   Server ID: {s['server_id'] or '-'}"
        if label:
            head = f"Vendor class {label}:  " + head
        ttk.Label(f, text=head, font=("TkDefaultFont", 11, "bold")).pack(
            anchor="w", padx=6, pady=(6, 2))
        changes = []
        if use_baseline and self.baseline is not None and n == 1:
            changes = compare(to_record(self.replies[0]), self.baseline)
        self._findings_panel(f, s["findings"], changes if use_baseline else None)

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
            for field, v in s["header"]:
                tv.insert("", "end", text="BOOTP", values=(field, v, ""), tags=("hdr",))
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
        self.nb.add(f, text=label or f"{n}: {s['source']} ({s['type']})")

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
        elif self.sweep_result:
            self.show_sweep(*self.sweep_result)

    def offer_elevation(self, msg):
        if _os() == "linux":
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
    def _export(self, kind):
        if self.v6_result:
            return (format_json6(self.v6_result) if kind == "json"
                    else format_text6(self.v6_result, self.show_raw.get()))
        if self.sweep_result:
            return (format_sweep_json if kind == "json" else format_sweep)(*self.sweep_result)
        if kind == "json":
            return format_json(self.replies)
        return format_text(self.replies, self.show_raw.get(), self.baseline)

    def copy_text(self):
        if not (self.replies or self.sweep_result or self.v6_result):
            return
        self.clipboard_clear()
        self.clipboard_append(self._export("txt"))
        self.status.set("Copied results to clipboard.")

    def save(self, kind):
        if not (self.replies or self.sweep_result or self.v6_result):
            messagebox.showinfo(APP, "Nothing to save yet.")
            return
        stem = "dhcp-sweep" if self.sweep_result else "dhcp-options"
        path = filedialog.asksaveasfilename(
            defaultextension=f".{kind}", initialfile=f"{stem}.{kind}",
            filetypes=[("JSON", "*.json")] if kind == "json" else [("Text", "*.txt")])
        if not path:
            return
        data = self._export(kind)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        self.status.set(f"Saved {os.path.basename(path)}")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
