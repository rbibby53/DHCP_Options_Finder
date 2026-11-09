#!/usr/bin/env python3
"""DHCP Options Finder GUI: Tkinter front end for dhcpprobe.py (Linux, macOS, Windows)."""
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import dhcpprobe as core

APP = "DHCP Options Finder"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP} {core.__version__}")
        self._set_icon()
        self.geometry("980x700")
        self.minsize(760, 520)
        self.replies = []
        self.q = queue.Queue()
        self.ifaces = []
        self._style()
        self._build()
        self.refresh_ifaces()
        self._priv_check()

    def _set_icon(self):
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        try:
            self._icon = tk.PhotoImage(file=os.path.join(base, "assets", "icon.png"))
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
        ttk.Button(macf, text="Random", width=8,
                   command=lambda: self.mac.set(core._hex(core.parse_mac("random")))).pack(
            side="left", padx=(4, 0))
        ttk.Label(cfg, text="Vendor class (60)").grid(row=2, column=3, sticky="e", **pad)
        self.vclass = tk.StringVar()
        ttk.Combobox(cfg, textvariable=self.vclass, values=[
            "", "PXEClient", "MSFT 5.0", "Cisco AP c9120", "ArubaAP", "ubnt", "udhcp"]).grid(
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
        ttk.Label(cfg, text="Blank MAC = interface MAC. Blank server = broadcast.",
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
        ttk.Label(bot, text="Double-click a row to see the full value. Ctrl/Cmd+C copies "
                            "selected rows.", style="Hint.TLabel").pack(side="right")

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
            self.ifaces = core.list_interfaces()
            d = core.default_interface(self.ifaces)
        except core.ProbeError as e:
            messagebox.showerror(APP, str(e))
            return
        labels = [f"{i['name']}  —  {i['ip'] or 'no IPv4'}  —  {i['mac']}"
                  f"{'' if i['up'] else '  (down)'}" for i in self.ifaces]
        self.iface_cb["values"] = labels
        if labels:
            idx = self.ifaces.index(d) if d in self.ifaces else 0
            self.iface_cb.current(idx)

    def _priv_check(self):
        if core.is_admin():
            return
        if sys.platform.startswith("linux"):
            self.warn.set("Not running as root. Probes will fail. Relaunch with sudo.")
        elif sys.platform == "darwin":
            self.warn.set("Not running as root. If the probe fails with a permission error, "
                          "relaunch with sudo.")

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
                mac=core.parse_mac(self.mac.get().strip()) if self.mac.get().strip() else None,
                vendor_class=self.vclass.get().strip() or None,
                hostname=self.hostname.get().strip() or None,
                request=core.parse_codes(self.req.get()) or list(range(1, 255)),
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
            self.q.put(("done", core.probe(**kw)))
        except core.ProbeError as e:
            self.q.put(("error", str(e)))
        except Exception as e:  # surface anything unexpected instead of hanging
            self.q.put(("error", f"{type(e).__name__}: {e}"))

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
                    messagebox.showerror(APP, val)
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
            ttk.Label(f, text=core.format_text([]), wraplength=700,
                      style="Hint.TLabel").pack(expand=True)
            self.nb.add(f, text="No replies")
            return
        self.nb.forget(self.nb.tabs()[0])
        sums = [core.summarize(p) for p in replies]
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

        if s["header"]:
            for label, v in s["header"]:
                tv.insert("", "end", text="BOOTP", values=(label, v, ""), tags=("hdr",))
        for o in s["options"]:
            iid = tv.insert("", "end", text=str(o["code"]),
                            values=(o["name"], o["values"][0], o["raw"]), open=True)
            for extra in o["values"][1:]:
                tv.insert(iid, "end", text="", values=("", extra, ""))

        tv.bind("<Double-1>", lambda e, t=tv: self._detail(t))
        mod = "Command" if sys.platform == "darwin" else "Control"
        tv.bind(f"<{mod}-c>", lambda e, t=tv: self._copy_rows(t))
        self.trees.append(tv)
        self._apply_raw(tv)
        self.nb.add(f, text=f"{n}: {s['source']} ({s['type']})")

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
        self.clipboard_append(core.format_text(self.replies, self.show_raw.get()))
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
        data = (core.format_json(self.replies) if kind == "json"
                else core.format_text(self.replies, self.show_raw.get()))
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        self.status.set(f"Saved {os.path.basename(path)}")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
