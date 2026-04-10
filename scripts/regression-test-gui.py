"""
Sigma Regression Test GUI
Launches a settings window to configure and run regression-test.py.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import json
import os
import sys
from pathlib import Path

# ── Config persistence ──────────────────────────────────────────────────────
CONFIG_FILE = Path(__file__).parent.parent / ".gui_config.json"

def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(data):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# ── Main window ─────────────────────────────────────────────────────────────
class RegressionTestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sigma Regression Test")
        self.root.resizable(True, True)
        self.process = None
        self._build_ui()
        self._load_saved()

    # ── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        # ── Top: settings notebook ──
        notebook = ttk.Notebook(self.root)
        notebook.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))

        self._build_splunk_tab(notebook)
        self._build_target_tab(notebook)
        self._build_test_tab(notebook)
        self._build_filters_tab(notebook)

        # ── Middle: run controls ──
        ctrl = ttk.Frame(self.root, padding=(10, 6))
        ctrl.grid(row=1, column=0, sticky="ew")
        ctrl.columnconfigure(1, weight=1)

        self.run_btn = ttk.Button(ctrl, text="▶  Run Tests", command=self._run)
        self.run_btn.grid(row=0, column=0, padx=(0, 8))

        self.stop_btn = ttk.Button(ctrl, text="⏹  Stop", command=self._stop, state="disabled")
        self.stop_btn.grid(row=0, column=1, sticky="w")

        ttk.Button(ctrl, text="Save Settings", command=self._save).grid(row=0, column=2, padx=(0, 4))
        ttk.Button(ctrl, text="Clear Output", command=self._clear_output).grid(row=0, column=3)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(ctrl, textvariable=self.status_var, foreground="#555").grid(
            row=0, column=4, padx=(12, 0), sticky="e")

        # ── Progress bar (hidden until running) ──
        self.progress = ttk.Progressbar(ctrl, mode="indeterminate", length=200)
        self.progress.grid(row=0, column=5, padx=(16, 0), sticky="e")
        self.progress.grid_remove()

        # ── Bottom: output ──
        out_frame = ttk.LabelFrame(self.root, text="Output", padding=6)
        out_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(4, 10))
        out_frame.columnconfigure(0, weight=1)
        out_frame.rowconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        self.output = scrolledtext.ScrolledText(
            out_frame, wrap=tk.WORD, font=("Consolas", 9),
            background="#1e1e1e", foreground="#d4d4d4",
            insertbackground="white", height=20
        )
        self.output.grid(row=0, column=0, sticky="nsew")
        self.output.tag_config("pass",  foreground="#4ec9b0")
        self.output.tag_config("fail",  foreground="#f44747")
        self.output.tag_config("info",  foreground="#9cdcfe")
        self.output.tag_config("warn",  foreground="#dcdcaa")
        self.output.tag_config("cmd",   foreground="#888888")

        self.root.minsize(720, 600)

    def _section(self, parent, label):
        """Thin labelled separator."""
        f = ttk.Frame(parent)
        ttk.Label(f, text=label, foreground="#666", font=("", 8, "bold")).pack(
            side="left", padx=(0, 6))
        ttk.Separator(f, orient="horizontal").pack(side="left", fill="x", expand=True)
        return f

    def _row(self, parent, label, row, col=0, width=28, show=None):
        """Label + Entry pair. Returns the StringVar."""
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="e", padx=(8, 4), pady=3)
        var = tk.StringVar()
        kw = {"textvariable": var, "width": width}
        if show:
            kw["show"] = show
        ttk.Entry(parent, **kw).grid(row=row, column=col + 1, sticky="ew", padx=(0, 8), pady=3)
        return var

    # ── Tabs ─────────────────────────────────────────────────────────────────

    def _build_splunk_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="  Splunk  ")
        f.columnconfigure(1, weight=1)
        f.columnconfigure(3, weight=1)

        self.splunk_host  = self._row(f, "Host",         0, 0, 30)
        self.splunk_port  = self._row(f, "Mgmt Port",    1, 0, 10)
        self.splunk_user  = self._row(f, "Username",     2, 0, 20)
        self.splunk_pass  = self._row(f, "Password",     3, 0, 20, show="•")
        self.splunk_web   = self._row(f, "Web Port",     0, 2, 10)
        self.splunk_app   = self._row(f, "App",          1, 2, 16)

        self.splunk_port.set("8089")
        self.splunk_web.set("8000")
        self.splunk_app.set("search")
        self.splunk_user.set("admin")

        ttk.Button(f, text="Test Connection", command=self._test_splunk).grid(
            row=4, column=0, columnspan=2, sticky="w", padx=8, pady=(10, 0))

    def _build_target_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="  Target  ")
        f.columnconfigure(1, weight=1)

        self.target_ip   = self._row(f, "Target IP",    0, 0, 30)
        self.winrm_user  = self._row(f, "WinRM User",   1, 0, 30)
        self.winrm_pass  = self._row(f, "WinRM Pass",   2, 0, 30, show="•")
        self.target_ip.set("localhost")

    def _build_test_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="  Test Settings  ")
        f.columnconfigure(1, weight=1)

        # Test config
        ttk.Label(f, text="Test Config").grid(row=0, column=0, sticky="e", padx=(8, 4), pady=3)
        self.test_config = tk.StringVar(value="tests/art_mapping.yaml")
        ttk.Entry(f, textvariable=self.test_config, width=36).grid(row=0, column=1, sticky="ew", padx=(0, 4), pady=3)
        ttk.Button(f, text="…", width=3, command=lambda: self._browse(self.test_config, [("YAML","*.yaml *.yml")])).grid(row=0, column=2, pady=3)

        # Output file
        ttk.Label(f, text="Output File").grid(row=1, column=0, sticky="e", padx=(8, 4), pady=3)
        self.output_file = tk.StringVar(value="test_results.json")
        ttk.Entry(f, textvariable=self.output_file, width=36).grid(row=1, column=1, sticky="ew", padx=(0, 4), pady=3)
        ttk.Button(f, text="…", width=3, command=lambda: self._browse_save(self.output_file, [("JSON","*.json")])).grid(row=1, column=2, pady=3)

        # Timing
        ttk.Label(f, text="Wait Time (s)").grid(row=2, column=0, sticky="e", padx=(8, 4), pady=3)
        self.wait_time = tk.StringVar(value="600")
        ttk.Entry(f, textvariable=self.wait_time, width=8).grid(row=2, column=1, sticky="w", padx=(0, 8), pady=3)

        ttk.Label(f, text="Lookback (min)").grid(row=3, column=0, sticky="e", padx=(8, 4), pady=3)
        self.lookback = tk.StringVar(value="60")
        ttk.Entry(f, textvariable=self.lookback, width=8).grid(row=3, column=1, sticky="w", padx=(0, 8), pady=3)
        ttk.Label(f, text="(leave blank for auto)", foreground="#888").grid(row=3, column=1, sticky="w", padx=(70, 0))

        # Flags
        self._section(f, "Execution Mode").grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 4))

        self.flag_parallel = tk.BooleanVar(value=True)
        self.flag_batch    = tk.BooleanVar(value=False)
        self.flag_dry_run  = tk.BooleanVar(value=False)
        self.flag_skip_chk = tk.BooleanVar(value=True)

        ttk.Checkbutton(f, text="--parallel  (5 concurrent WinRM sessions, implies --batch)",
                        variable=self.flag_parallel).grid(row=5, column=0, columnspan=3, sticky="w", padx=12)
        ttk.Checkbutton(f, text="--batch  (sequential, single wait)",
                        variable=self.flag_batch).grid(row=6, column=0, columnspan=3, sticky="w", padx=12)
        ttk.Checkbutton(f, text="--dry-run  (show test plan, no execution)",
                        variable=self.flag_dry_run).grid(row=7, column=0, columnspan=3, sticky="w", padx=12)
        ttk.Checkbutton(f, text="--skip-atomic-check  (skip ART install verification)",
                        variable=self.flag_skip_chk).grid(row=8, column=0, columnspan=3, sticky="w", padx=12)

    def _build_filters_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="  Filters  ")
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="One per line. Leave blank to run all tests.", foreground="#888").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(0, 8))

        for i, (label, attr) in enumerate([
            ("Technique IDs\n(e.g. T1018)", "filter_technique"),
            ("Expected Rules\n(partial match)", "filter_rule"),
            ("Atomic Test GUIDs", "filter_guid"),
        ]):
            ttk.Label(f, text=label, justify="right").grid(row=i + 1, column=0, sticky="ne", padx=(8, 4), pady=4)
            t = tk.Text(f, height=3, width=40, font=("Consolas", 9))
            t.grid(row=i + 1, column=1, sticky="ew", padx=(0, 8), pady=4)
            setattr(self, attr, t)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _browse(self, var, filetypes):
        p = filedialog.askopenfilename(filetypes=filetypes)
        if p:
            var.set(p)

    def _browse_save(self, var, filetypes):
        p = filedialog.asksaveasfilename(filetypes=filetypes, defaultextension=filetypes[0][1].split()[0].lstrip("*"))
        if p:
            var.set(p)

    def _lines(self, widget):
        return [l.strip() for l in widget.get("1.0", tk.END).strip().splitlines() if l.strip()]

    # ── Config persistence ────────────────────────────────────────────────────

    def _save(self):
        save_config(self._collect_config())
        self.status_var.set("Settings saved.")

    def _collect_config(self):
        return {
            "splunk_host":   self.splunk_host.get(),
            "splunk_port":   self.splunk_port.get(),
            "splunk_user":   self.splunk_user.get(),
            "splunk_pass":   self.splunk_pass.get(),
            "splunk_web":    self.splunk_web.get(),
            "splunk_app":    self.splunk_app.get(),
            "target_ip":     self.target_ip.get(),
            "winrm_user":    self.winrm_user.get(),
            "winrm_pass":    self.winrm_pass.get(),
            "test_config":   self.test_config.get(),
            "output_file":   self.output_file.get(),
            "wait_time":     self.wait_time.get(),
            "lookback":      self.lookback.get(),
            "parallel":      self.flag_parallel.get(),
            "batch":         self.flag_batch.get(),
            "dry_run":       self.flag_dry_run.get(),
            "skip_chk":      self.flag_skip_chk.get(),
            "filter_technique": self.filter_technique.get("1.0", tk.END),
            "filter_rule":      self.filter_rule.get("1.0", tk.END),
            "filter_guid":      self.filter_guid.get("1.0", tk.END),
        }

    def _load_saved(self):
        cfg = load_config()
        if not cfg:
            return
        def sv(var, key):
            if key in cfg:
                var.set(cfg[key])
        def tv(widget, key):
            if key in cfg and cfg[key].strip():
                widget.delete("1.0", tk.END)
                widget.insert("1.0", cfg[key])

        sv(self.splunk_host, "splunk_host");  sv(self.splunk_port, "splunk_port")
        sv(self.splunk_user, "splunk_user");  sv(self.splunk_pass, "splunk_pass")
        sv(self.splunk_web,  "splunk_web");   sv(self.splunk_app,  "splunk_app")
        sv(self.target_ip,   "target_ip");    sv(self.winrm_user,  "winrm_user")
        sv(self.winrm_pass,  "winrm_pass");   sv(self.test_config, "test_config")
        sv(self.output_file, "output_file");  sv(self.wait_time,   "wait_time")
        sv(self.lookback,    "lookback")
        if "parallel" in cfg: self.flag_parallel.set(cfg["parallel"])
        if "batch"    in cfg: self.flag_batch.set(cfg["batch"])
        if "dry_run"  in cfg: self.flag_dry_run.set(cfg["dry_run"])
        if "skip_chk" in cfg: self.flag_skip_chk.set(cfg["skip_chk"])
        tv(self.filter_technique, "filter_technique")
        tv(self.filter_rule,      "filter_rule")
        tv(self.filter_guid,      "filter_guid")

    # ── Command builder ───────────────────────────────────────────────────────

    def _build_cmd(self):
        """Return cmd_list.

        Arguments are passed as a list to subprocess.Popen (shell=False),
        so special characters in passwords are never shell-interpreted.
        """
        script = Path(__file__).parent / "regression-test.py"
        cmd = [sys.executable, str(script)]

        def req(flag, val, name):
            if not val.strip():
                raise ValueError(f"{name} is required.")
            cmd.extend([flag, val.strip()])

        def opt(flag, val):
            if val.strip():
                cmd.extend([flag, val.strip()])

        if not self.flag_dry_run.get():
            req("--splunk-host", self.splunk_host.get(), "Splunk Host")
            opt("--splunk-port", self.splunk_port.get())
            opt("--splunk-user", self.splunk_user.get())
            opt("--splunk-pass", self.splunk_pass.get())
            opt("--splunk-web-port", self.splunk_web.get())
            opt("--splunk-app",  self.splunk_app.get())
            opt("--target",      self.target_ip.get())
            opt("--winrm-user",  self.winrm_user.get())
            opt("--winrm-pass",  self.winrm_pass.get())
            opt("--wait-time",   self.wait_time.get())
            opt("--lookback-window", self.lookback.get())
        else:
            opt("--splunk-host", self.splunk_host.get())

        opt("--test-config", self.test_config.get())
        opt("--output",      self.output_file.get())

        if self.flag_parallel.get():
            cmd.append("--parallel")
        elif self.flag_batch.get():
            cmd.append("--batch")

        if self.flag_dry_run.get():
            cmd.append("--dry-run")
        if self.flag_skip_chk.get():
            cmd.append("--skip-atomic-check")

        for t in self._lines(self.filter_technique):
            cmd += ["--technique", t]
        for r in self._lines(self.filter_rule):
            cmd += ["--expected-rule", r]
        for g in self._lines(self.filter_guid):
            cmd += ["--test-id", g]

        return cmd

    # ── Execution ─────────────────────────────────────────────────────────────

    def _test_splunk(self):
        """Quick auth test against Splunk REST API — runs in background thread."""
        host = self.splunk_host.get().strip()
        port = self.splunk_port.get().strip() or "8089"
        user = self.splunk_user.get().strip()
        password = self.splunk_pass.get().strip()
        if not host or not password:
            messagebox.showerror("Missing fields", "Splunk Host and Password are required.")
            return

        self._append(f"Testing connection to https://{host}:{port} as {user}…\n", "info")

        def _do_test():
            try:
                import requests, urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                url = f"https://{host}:{port}/services/search/jobs"
                r = requests.post(url, data={"search": "search index=_internal | head 1",
                                             "output_mode": "json"},
                                  auth=(user, password), verify=False, timeout=10)
                if r.status_code == 201:
                    self.root.after(0, self._append, "  Connection OK (HTTP 201)\n", "pass")
                elif r.status_code == 401:
                    self.root.after(0, self._append,
                        f"  Auth FAILED (401) — wrong username/password for the REST API.\n"
                        f"  Tip: verify with:  curl -k -u {user}:PASSWORD "
                        f"https://{host}:{port}/services/search/jobs\n", "fail")
                else:
                    self.root.after(0, self._append,
                        f"  Unexpected response: HTTP {r.status_code}\n  {r.text[:200]}\n", "warn")
            except Exception as e:
                self.root.after(0, self._append, f"  Error: {e}\n", "fail")

        threading.Thread(target=_do_test, daemon=True).start()

    def _run(self):
        try:
            cmd = self._build_cmd()
        except ValueError as e:
            messagebox.showerror("Missing required field", str(e))
            return

        self._clear_output()

        # Show the command with password values masked
        _pass_flags = {"--splunk-pass", "--winrm-pass"}
        masked_parts = []
        hide_next = False
        for token in cmd:
            if hide_next:
                masked_parts.append("***")
                hide_next = False
            elif token in _pass_flags:
                masked_parts.append(token)
                hide_next = True
            else:
                masked_parts.append(f'"{token}"' if " " in token else token)
        self._append("$ " + " ".join(masked_parts) + "\n\n", "cmd")

        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("** TEST RUNNING **")
        self.progress.grid()
        self.progress.start(12)
        self._save()

        def worker():
            try:
                env = {**os.environ, "PYTHONUNBUFFERED": "1"}
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env,
                    cwd=str(Path(__file__).parent.parent),
                )
                for line in self.process.stdout:
                    self.root.after(0, self._append_line, line)
                self.process.wait()
                rc = self.process.returncode
                self.root.after(0, self._done, rc)
            except Exception as e:
                self.root.after(0, self._append, f"\nError: {e}\n", "fail")
                self.root.after(0, self._done, 1)

        threading.Thread(target=worker, daemon=True).start()

    def _stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self._append("\n[Stopped by user]\n", "warn")
        self.progress.stop()
        self.progress.grid_remove()
        self._done(None)

    def _done(self, rc):
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress.stop()
        self.progress.grid_remove()
        if rc is None:
            self.status_var.set("Stopped.")
            return
        elif rc == 0:
            self.status_var.set("Finished — all done.")
            self._append("\n✔  Run complete.\n", "pass")
        else:
            self.status_var.set(f"Finished with exit code {rc}.")
            self._append(f"\n✘  Run finished with exit code {rc}.\n", "fail")

        # Offer to open the HTML results file
        out = self.output_file.get().strip()
        if out:
            html_path = Path(__file__).parent.parent / Path(out).with_suffix(".html")
            if html_path.exists():
                if messagebox.askyesno(
                    "Run complete",
                    f"Tests finished.\n\nOpen HTML results?\n{html_path}",
                ):
                    os.startfile(str(html_path))

    # ── Output rendering ──────────────────────────────────────────────────────

    def _clear_output(self):
        self.output.config(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.config(state="normal")

    def _append(self, text, tag=None):
        self.output.config(state="normal")
        if tag:
            self.output.insert(tk.END, text, tag)
        else:
            self.output.insert(tk.END, text)
        self.output.see(tk.END)

    def _append_line(self, line):
        tag = None
        l = line.rstrip()
        if "Result: PASS" in l or l.strip().startswith("[+]"):
            tag = "pass"
        elif "Result: FAIL" in l or l.strip().startswith("[-]"):
            tag = "fail"
        elif l.startswith("[BATCH MODE]") or l.startswith("All atomics") or "Waiting" in l:
            tag = "info"
        elif "FAILED" in l or "Error" in l:
            tag = "warn"
        self._append(line, tag)


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()

    # Try to apply a modern theme
    style = ttk.Style(root)
    for theme in ("vista", "winnative", "clam"):
        if theme in style.theme_names():
            style.theme_use(theme)
            break

    app = RegressionTestGUI(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        import tkinter as _tk
        from tkinter import messagebox as _mb
        _r = _tk.Tk()
        _r.withdraw()
        _mb.showerror("Startup error", str(exc))
        _r.destroy()
        raise
