#!/usr/bin/env python3
import json
import os
import signal
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ROOT = Path(__file__).resolve().parent
VAULT_PATH = Path.home() / ".vault/vault.json"
VAULT_EXECUTABLE_PATH_FILE = Path.home() / ".vault/vault_executable_path"

def find_binary() -> Path:
    override = os.environ.get("VAULT_BIN")
    if override:
        return Path(override)

    if VAULT_EXECUTABLE_PATH_FILE.exists():
        try:
            saved = Path(VAULT_EXECUTABLE_PATH_FILE.read_text().strip()).expanduser()
            if saved.exists():
                return saved
        except OSError:
            pass

    for candidate in (
        ROOT / "target" / "release" / "vault",
        ROOT / "target" / "debug" / "vault",
    ):
        if candidate.exists():
            return candidate
    return ROOT / "target" / "debug" / "vault"


BIN = find_binary()


def run_vault(file_path: str, args: list[str], passwords: list[str]):
    """Run the vault binary, feeding passwords via stdin."""
    command = [str(BIN), "--file", file_path, "--stdin", *args]
    data = "\n".join(passwords) + "\n"
    return subprocess.run(command, input=data, capture_output=True, text=True)


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, site: str, username: str, password: str):
        super().__init__(parent)
        self.title(site)
        self.resizable(False, False)
        self.password = password
        self.revealed = False

        ttk.Label(self, text="Site:").grid(row=0, column=0, sticky="e", padx=8, pady=(8, 2))
        ttk.Label(self, text=site).grid(row=0, column=1, sticky="w", padx=8, pady=(8, 2))
        ttk.Label(self, text="Username:").grid(row=1, column=0, sticky="e", padx=8, pady=2)
        ttk.Label(self, text=username).grid(row=1, column=1, sticky="w", padx=8, pady=2)
        ttk.Label(self, text="Password:").grid(row=2, column=0, sticky="e", padx=8, pady=2)

        self.pw_var = tk.StringVar(value=password)
        self.pw_entry = ttk.Entry(
            self, textvariable=self.pw_var, show="*", state="readonly", width=30
        )
        self.pw_entry.grid(row=2, column=1, sticky="w", padx=8, pady=2)

        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, foreground="green").grid(
            row=3, column=0, columnspan=2, sticky="w", padx=8
        )

        buttons = ttk.Frame(self, padding=8)
        buttons.grid(row=4, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Close", command=self.destroy).pack(side="right")
        self.view_button = ttk.Button(buttons, text="View", command=self.toggle_view)
        self.view_button.pack(side="right", padx=4)
        ttk.Button(buttons, text="Copy", command=self.copy).pack(side="right", padx=4)

        self.transient(parent)
        self.update_idletasks()
        self._try_grab()
        self._center_over(parent)

    def _try_grab(self):
        try:
            self.grab_set()
        except tk.TclError:
            pass

    def _center_over(self, parent):
        self.update_idletasks()
        x = parent.winfo_screenwidth() // 2 - self.winfo_width() // 2
        y = parent.winfo_screenheight() // 2 - self.winfo_height() // 2
        self.geometry(f"+{x}+{y}")

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.password)
        self.status_var.set("Copied!")

    def toggle_view(self):
        self.revealed = not self.revealed
        self.pw_entry.config(show="" if self.revealed else "*")
        self.view_button.config(text="Hide" if self.revealed else "View")


class EntryDialog(tk.Toplevel):
    """Small modal form used for adding a new entry."""

    def __init__(self, parent, title, fields):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result = None

        self.vars = []
        for row, (label, masked) in enumerate(fields):
            ttk.Label(self, text=label).grid(row=row, column=0, sticky="w", padx=8, pady=4)
            var = tk.StringVar()
            entry = ttk.Entry(self, textvariable=var, show="*" if masked else "", width=34)
            entry.grid(row=row, column=1, sticky="we", padx=8, pady=4)
            self.vars.append(var)
            if row == 0:
                entry.focus_set()

        self.columnconfigure(1, weight=1)

        buttons = ttk.Frame(self, padding=8)
        buttons.grid(row=len(fields), column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="OK", command=self._ok).pack(side="right", padx=4)

        self.bind("<Return>", lambda _event: self._ok())
        self.transient(parent)
        self.update_idletasks()
        self._try_grab()

    def _try_grab(self):
        try:
            self.grab_set()
        except tk.TclError:
            pass

    def _ok(self):
        self.result = [var.get() for var in self.vars]
        self.destroy()


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.vault_path = VAULT_PATH
        self.master = None

        root.title("Vault")
        root.geometry("560x400")

        self._build_login()
        self._build_main()
        self._show_login()


    def _run_async(self, args, passwords, on_success, on_error):
        def worker():
            proc = run_vault(str(self.vault_path), args, passwords)
            try:
                if proc.returncode == 0:
                    self.root.after(0, lambda: on_success(proc.stdout))
                else:
                    self.root.after(0, lambda: on_error(proc.stderr))
            except tk.TclError:
                pass

        threading.Thread(target=worker, daemon=True).start()


    def _build_login(self):
        self.login_frame = ttk.Frame(self.root, padding=24)
        creating = not self.vault_path.exists()

        title = "Create a master password" if creating else "Unlock your vault"
        ttk.Label(self.login_frame, text=title, font=("", 13, "bold")).pack(
            anchor="w", pady=(0, 12)
        )

        ttk.Label(self.login_frame, text="Master password:").pack(anchor="w")
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=42)
        self.password_entry.pack(anchor="w", fill="x", pady=(0, 8))

        self.confirm_label = ttk.Label(self.login_frame, text="Confirm password:")
        self.confirm_entry = ttk.Entry(self.login_frame, show="*", width=42)
        if creating:
            self.confirm_label.pack(anchor="w")
            self.confirm_entry.pack(anchor="w", fill="x", pady=(0, 8))

        self.login_error = tk.StringVar()
        ttk.Label(self.login_frame, textvariable=self.login_error, foreground="red").pack(
            anchor="w"
        )

        self.submit_button = ttk.Button(
            self.login_frame,
            text="Create Vault" if creating else "Unlock",
            command=self._submit_login,
        )
        self.submit_button.pack(anchor="e", pady=(12, 0))

        self.password_entry.bind("<Return>", lambda _event: self._submit_login())
        self.confirm_entry.bind("<Return>", lambda _event: self._submit_login())
        self.password_entry.focus_set()

    def _show_login(self):
        self.main_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.password_entry.focus_set()

    def _submit_login(self):
        password = self.password_entry.get()
        creating = not self.vault_path.exists()

        if creating:
            if not password:
                self.login_error.set("Password cannot be empty.")
                return
            if password != self.confirm_entry.get():
                self.login_error.set("Passwords do not match.")
                return
            args = ["init"]
            passwords = [password, password]
        else:
            args = ["--json", "list"]
            passwords = [password]

        self.submit_button.config(state="disabled")
        self.login_error.set("Creating…" if creating else "Unlocking…")

        def on_success(_stdout):
            self.master = password
            self.password_entry.delete(0, "end")
            self.confirm_entry.delete(0, "end")
            self._show_main()

        def on_error(stderr):
            if creating:
                self.login_error.set(stderr.strip() or "Failed to create vault.")
            else:
                self.login_error.set("Incorrect master password.")
                self.password_entry.delete(0, "end")
            self.submit_button.config(state="normal")
            self.password_entry.focus_set()

        self._run_async(args, passwords, on_success, on_error)

    # --- main (vault) screen -------------------------------------------

    def _build_main(self):
        self.main_frame = ttk.Frame(self.root, padding=8)

        buttons = ttk.Frame(self.main_frame, padding=(0, 0, 0, 8))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Add Entry", command=self.add_entry).pack(side="left")
        ttk.Button(buttons, text="Remove Entry", command=self.remove_entry).pack(
            side="left", padx=4
        )

        tree_frame = ttk.Frame(self.main_frame)
        tree_frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(
            tree_frame, columns=("site", "username"), show="headings"
        )
        self.tree.heading("site", text="Site")
        self.tree.heading("username", text="Username")
        self.tree.column("site", width=260)
        self.tree.column("username", width=260)
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self.on_double_click)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(
            self.main_frame, textvariable=self.status, relief="sunken", anchor="w", padding=4
        ).pack(fill="x")

    def _show_main(self):
        self.login_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)
        self._refresh()


    def selected_site(self):
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0]).get("values")
        if not values:
            return None
        return str(values[0])

    def _show_error(self, message: str):
        text = message.strip() or "Unknown error"
        self.status.set(f"Error: {text}")
        messagebox.showerror("Vault", text)

    # --- actions --------------------------------------------------------

    def _refresh(self):
        def on_success(stdout):
            try:
                entries = json.loads(stdout)
            except json.JSONDecodeError as exc:
                self._show_error(f"Bad output from vault: {exc}")
                return
            self.tree.delete(*self.tree.get_children())
            for entry in entries:
                self.tree.insert("", "end", values=(entry["site"], entry["username"]))
            count = len(entries)
            self.status.set(f"{count} entr{'y' if count == 1 else 'ies'}.")

        def on_error(stderr):
            self._show_error(stderr)

        self._run_async(["--json", "list"], [self.master], on_success, on_error)

    def add_entry(self):
        dialog = EntryDialog(
            self.root,
            "Add entry",
            [("Site", False), ("Username", False), ("Password", True)],
        )
        self.root.wait_window(dialog)
        values = dialog.result
        if not values or any(not value for value in values):
            return

        site, username, entry_password = values

        def on_success(_stdout):
            self.status.set(f"Added {site}.")
            self._refresh()

        def on_error(stderr):
            self._show_error(stderr)

        self._run_async(
            ["add", "--site", site, "--username", username],
            [self.master, entry_password],
            on_success,
            on_error,
        )

    def remove_entry(self):
        site = self.selected_site()
        if not site:
            self.status.set("Select an entry first.")
            return

        if not messagebox.askyesno("Remove", f"Remove entry '{site}'?"):
            return

        def on_success(_stdout):
            self.status.set(f"Removed {site}.")
            self._refresh()

        def on_error(stderr):
            self._show_error(stderr)

        self._run_async(["remove", site], [self.master], on_success, on_error)

    def on_double_click(self, _event):
        site = self.selected_site()
        if not site:
            return

        def on_success(stdout):
            try:
                entry = json.loads(stdout)
            except json.JSONDecodeError as exc:
                self._show_error(f"Bad output from vault: {exc}")
                return
            PasswordDialog(self.root, entry["site"], entry["username"], entry["password"])

        def on_error(stderr):
            self._show_error(stderr)

        self._run_async(["--json", "get", site], [self.master], on_success, on_error)


def main():
    global BIN

    if not BIN.exists():
        root = tk.Tk()
        root.withdraw()
        selected = filedialog.askopenfilename(
            title="Select the vault executable",
            initialdir=str(ROOT),
        )
        if not selected:
            root.destroy()
            sys.exit(1)

        path = Path(selected).expanduser().resolve()

        try:
            VAULT_EXECUTABLE_PATH_FILE.parent.mkdir(parents=True, exist_ok=True)
            VAULT_EXECUTABLE_PATH_FILE.write_text(str(path))
        except OSError as exc:
            messagebox.showerror(
                "Vault",
                f"Could not save the executable path to {VAULT_EXECUTABLE_PATH_FILE}:\n{exc}",
            )
            root.destroy()
            sys.exit(1)

        BIN = path
        root.destroy()

    root = tk.Tk()
    App(root)

    def handle_sigint(_signum, _frame):
        root.quit()

    signal.signal(signal.SIGINT, handle_sigint)

    def poll_signal():
        root.after(100, poll_signal)

    poll_signal()
    root.mainloop()


if __name__ == "__main__":
    main()
