"""
MAO Windows Reclaimer
Geliştirici: Miraç Alp
Dosya: mao_windows_reclaimer_all.py

Kurulu Windows uygulamalarını (AppX/UWP ve MSI/Win32) listeler, kullanıcının
corumlu olmayan uygulamaları seçmesine izin verir ve onay sonrası kaldırır.
Kaldırma işlemi başlamadan önce her işlemin JSON günlüğü yedek klasörüne yazılır.

Yalnızca Windows 10/11. Yalnızca standart kütüphane + tkinter + subprocess.
Çalıştırma: python app.py  (veya python mao_windows_reclaimer_all.py)
"""

import ctypes
import datetime
import getpass
import json
import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

APP_NAME = "MAO Windows Reclaimer"
DEVELOPER = "Miraç Alp"
APP_VERSION = "1.0.0"

TYPE_APPX = "AppX/UWP"
TYPE_MSI = "MSI/Win32"

# ---------------------------------------------------------------------------
# Protection rules
# ---------------------------------------------------------------------------
# Matched case-insensitively against the app's name, package family name,
# publisher and install location. Any match marks the app as protected.
PROTECTED_KEYWORDS = [
    "microsoft.edge",
    "msedge",
    "microsoft edge",
    "webview2",
    "microsoft edge webview",
    "windows defender",
    "defender",
    "windows security",
    "securityhealth",
    "microsoft.windows.securityhealth",
    "windows update",
    "update health",
    "windowsupdate",
    "windows firewall",
    "windows installer",
    "windows.immersivecontrolpanel",
    "microsoft.windows.shellexperiencehost",
    "microsoft.windows.startmenuexperiencehost",
    "microsoft.windows.cortana",
    "microsoft.windows.search",
    "microsoft.windows.photos",  # kept: core photo viewer dependency
    "microsoft.windowsstore",
    "microsoft store",
    "store installer",
    "microsoft.desktopappinstaller",
    "app installer",
    "microsoft.vclibs",
    "microsoft.ui.xaml",
    "microsoft.net.native",
    "microsoft.windows.capturepicker",
    "microsoft.windows.contentdeliverymanager",
    "microsoft.windows.shellexperiencehost",
    "microsoft.accountscontrol",
    "microsoft.aad.brokerplugin",
    "microsoft.login",
    "microsoft.lockapp",
    "microsoft.windows.peopleexperiencehost",
    "microsoft.windows.assignedaccess",
    "microsoft.windows.appresolver",
    "microsoft.windows.apprep",
    "microsoft.windows.xgpuejectdialog",
    "microsoft.windows.overlay",
    "microsoft.windows.sechealthui",
    "windows.cloudexperiencehost",
    "windows.printdialog",
    "windows.ui.xaml",
    "microsoft.windows.startmenu",
    "microsoft.windows.taskbar",
    "microsoft.windows.shellexperience",
    "microsoft.windows.dynamicfolder",
    "microsoft.windowscommunicationsapps",
    "microsoft.windows.devicecredentialdialog",
    "microsoft.windows.opensshserver",
    "microsoft.549981c3f5f10",  # Cortana
    "microsoft.ui",
    "windows.client",
    "windows.cbspreview",
    "windows.devices",
    "windows.immersivecontrolpanel",
    "nvidia",  # Varsayılan olarak korunmaz; aşağıya bakın
]

# Keywords that are guaranteed-protected only when they appear as a *prefix*
# of an AppX package name (system packages all start with these).
PROTECTED_PREFIXES = [
    "microsoft.windows.",
    "windows.",
    "microsoft.ui.",
    "microsoft.net.",
    "microsoft.vclibs",
    "microsoft.services.store",
    "microsoft.storepurchaseapp",
    "microsoft.winappruntime",
    "microsoft.549981c3f5f10",
]

# Yukarıdaki NVIDIA girişi bilerek etkin korumadan çıkarılır;
# çünkü bu bir üçüncü taraf sürücü paketidir, Windows çekirdek bileşeni değildir.
PROTECTED_KEYWORDS = [k for k in PROTECTED_KEYWORDS if k != "nvidia"]

# MSI products whose names identify core Windows / Microsoft runtime components.
MSI_PROTECTED_KEYWORDS = [
    "webview2",
    "microsoft edge",
    "windows defender",
    "defender",
    "windows security",
    "windows update",
    "windows installer",
    "windows firewall",
    "microsoft windows",
    "windows sdk",
    "microsoft .net",
    "microsoft visual c++",
    "vc++ redistributable",
    "microsoft update health",
    "security update",
    "update for windows",
    "hotfix",
    "microsoft store",
    "windows software development kit",
    "microsoft gameinput",
]

# Windows-owned publisher strings. A product from these publishers is protected
# unless it is clearly a third-party product.
PROTECTED_PUBLISHERS = [
    "microsoft corporation",
    "microsoft",
]

# Among Microsoft publishers, the following still count as user-removable.
MICROSOFT_REMOVABLE_KEYWORDS = [
    "office",
    "teams",
    "onedrive",
    "skype",
    "visual studio",
    "powertoys",
    "power bi",
    "clipchamp",
    "paint 3d",
    "xbox",
    "solitaire",
    "to do",
    "sticky notes",
    "mixed reality",
    "feedback hub",
    "get help",
    "tips",
    "news",
    "weather",
    "movies & tv",
    "groove",
    "maps",
    "mail and calendar",
    "3d viewer",
]


def is_protected(name, package_id="", publisher="", location=""):
    """(korunuyor: bool, neden: str) döndürür."""
    haystack = " ".join([name or "", package_id or "", publisher or "", location or ""]).lower()
    name_l = (name or "").lower()
    pkg_l = (package_id or "").lower()
    pub_l = (publisher or "").lower()

    for kw in PROTECTED_KEYWORDS:
        if kw in haystack:
            return True, f"Korumalı bileşenle eşleşiyor '{kw}'"

    for prefix in PROTECTED_PREFIXES:
        if pkg_l.startswith(prefix) or name_l.startswith(prefix):
            return True, f"Çekirdek Windows paket öneki '{prefix}'"

    # Microsoft-published items: protected unless explicitly removable.
    if any(pub_l.startswith(p) for p in PROTECTED_PUBLISHERS):
        if not any(kw in haystack for kw in MICROSOFT_REMOVABLE_KEYWORDS):
            return True, "Microsoft sistem bileşeni"

    return False, ""


def is_msi_protected(name, publisher=""):
    """Win32/MSI kayıtları için (korunuyor: bool, neden: str) döndürür."""
    name_l = (name or "").lower()
    pub_l = (publisher or "").lower()

    for kw in MSI_PROTECTED_KEYWORDS:
        if kw in name_l:
            return True, f"Korumalı bileşenle eşleşiyor '{kw}'"

    if any(pub_l.startswith(p) for p in PROTECTED_PUBLISHERS):
        if not any(kw in name_l for kw in MICROSOFT_REMOVABLE_KEYWORDS):
            return True, "Microsoft sistem bileşeni"

    return False, ""


# ---------------------------------------------------------------------------
# Windows helpers
# ---------------------------------------------------------------------------
CREATE_NO_WINDOW = 0x08000000


def ensure_windows():
    if sys.platform != "win32":
        raise SystemExit("MAO Windows Reclaimer yalnızca Windows 10/11 üzerinde çalışır.")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_powershell(script, timeout=600):
    """PowerShell betiğini çalıştırır ve stdout metnini döndürür. Hata durumunda RuntimeError fırlatır."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script,
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"PowerShell {proc.returncode} koduyla sonlandı")
    return proc.stdout


def parse_json_output(text):
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        return [data]
    return data


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def list_appx_packages():
    script = (
        "Get-AppxPackage | Where-Object { $_.IsFramework -eq $false -and $_.NonRemovable -eq $false } "
        "| Select-Object Name, PackageFullName, PackageFamilyName, Publisher, InstallLocation, "
        "Version, SignatureKind, IsFramework "
        "| ConvertTo-Json -Depth 2 -Compress"
    )
    items = parse_json_output(run_powershell(script))
    apps = []
    for item in items:
        name = item.get("Name") or ""
        full = item.get("PackageFullName") or name
        family = item.get("PackageFamilyName") or ""
        publisher = item.get("Publisher") or ""
        location = item.get("InstallLocation") or ""
        protected, reason = is_protected(name, family or full, publisher, location)
        apps.append({
            "name": name,
            "display_name": name,
            "type": TYPE_APPX,
            "id": full,
            "publisher": publisher,
            "version": item.get("Version") or "",
            "location": location,
            "protected": protected,
            "protect_reason": reason,
        })
    return apps


def list_msi_products():
    script = (
        "Get-CimInstance -ClassName Win32_Product "
        "| Select-Object Name, Vendor, Version, IdentifyingNumber, InstallLocation "
        "| ConvertTo-Json -Depth 2 -Compress"
    )
    items = parse_json_output(run_powershell(script, timeout=900))
    apps = []
    for item in items:
        name = item.get("Name") or ""
        if not name:
            continue
        vendor = item.get("Vendor") or ""
        protected, reason = is_msi_protected(name, vendor)
        apps.append({
            "name": name,
            "display_name": name,
            "type": TYPE_MSI,
            "id": item.get("IdentifyingNumber") or "",
            "publisher": vendor,
            "version": item.get("Version") or "",
            "location": item.get("InstallLocation") or "",
            "protected": protected,
            "protect_reason": reason,
        })
    return apps


def scan_all_apps():
    apps = []
    errors = []
    try:
        apps.extend(list_appx_packages())
    except Exception as exc:
        errors.append(f"AppX taraması başarısız: {exc}")
    try:
        apps.extend(list_msi_products())
    except Exception as exc:
        errors.append(f"MSI taraması başarısız: {exc}")

    apps.sort(key=lambda a: (a["protected"], a["name"].lower()))
    return apps, errors


# ---------------------------------------------------------------------------
# Removal
# ---------------------------------------------------------------------------
def backup_dir():
    user = getpass.getuser()
    path = os.path.join(f"C:\\Users\\{user}", "MAO-Reclaimer-Backup")
    os.makedirs(path, exist_ok=True)
    return path


def write_removal_log(entries):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(backup_dir(), f"removal_log_{stamp}.json")
    payload = {
        "uygulama": APP_NAME,
        "gelistirici": DEVELOPER,
        "surum": APP_VERSION,
        "olusturulma_zamani": datetime.datetime.now().isoformat(timespec="seconds"),
        "kayitlar": entries,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path


def _ps_quote(value):
    """Değeri tek tırnaklı güvenli bir PowerShell literali olarak tırnaklar."""
    return "'" + str(value).replace("'", "''") + "'"


def remove_appx(app):
    package = app["id"]
    if not re.fullmatch(r"[A-Za-z0-9.\-_~+]+", package):
        raise ValueError("Güvensiz paket kimliği reddedildi")
    script = f"Remove-AppxPackage -Package {_ps_quote(package)} -ErrorAction Stop"
    run_powershell(script, timeout=900)


def remove_msi(app):
    product_code = app["id"]
    if not re.fullmatch(r"\{[0-9A-Fa-f\-]{36}\}", product_code):
        raise ValueError("Geçersiz MSI ürün kodu reddedildi")
    cmd = ["msiexec.exe", "/x", product_code, "/qn", "/norestart"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800,
                          creationflags=CREATE_NO_WINDOW)
    # 0 = success, 3010 = success, reboot required
    if proc.returncode not in (0, 3010):
        raise RuntimeError(f"msiexec {proc.returncode} koduyla sonlandı")


def remove_app(app):
    if app["type"] == TYPE_APPX:
        remove_appx(app)
    elif app["type"] == TYPE_MSI:
        remove_msi(app)
    else:
        raise ValueError("Bilinmeyen uygulama türü")


def remove_apps(apps, progress_cb=None):
    """Uygulamaları tek tek kaldırır. Korunan uygulamalar son güvenlik kontrolü olarak burada reddedilir."""
    results = []
    for index, app in enumerate(apps, start=1):
        entry = {
            "name": app["name"],
            "type": app["type"],
            "id": app["id"],
            "publisher": app["publisher"],
            "version": app["version"],
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        if app.get("protected"):
            entry["status"] = "skipped_protected"
            entry["error"] = app.get("protect_reason", "Korumalı")
        else:
            try:
                remove_app(app)
                entry["status"] = "removed"
                entry["error"] = None
            except Exception as exc:
                entry["status"] = "failed"
                entry["error"] = str(exc)
        results.append(entry)
        if progress_cb:
            progress_cb(index, len(apps), app["name"])
    return results


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
COLORS = {
    "bg": "#0f1419",
    "panel": "#1a212b",
    "accent": "#3b82f6",
    "accent_hover": "#2563eb",
    "text": "#e6edf3",
    "muted": "#8b98a5",
    "danger": "#ef4444",
    "success": "#22c55e",
    "row_protected": "#2a1f1f",
    "row_normal": "#1a212b",
}


class ReclaimerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  •  {DEVELOPER}")
        self.geometry("1000x640")
        self.minsize(820, 520)
        self.configure(bg=COLORS["bg"])

        self.apps = []
        self.item_map = {}
        self.queue = queue.Queue()
        self.busy = False

        self._setup_style()
        self._build_ui()
        self.after(100, self._poll_queue)
        self.after(200, self.refresh_apps)

    # -- styling ------------------------------------------------------------
    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview",
                        background=COLORS["panel"],
                        fieldbackground=COLORS["panel"],
                        foreground=COLORS["text"],
                        rowheight=26,
                        borderwidth=0,
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                        background=COLORS["bg"],
                        foreground=COLORS["text"],
                        font=("Segoe UI Semibold", 10),
                        relief="flat")
        style.map("Treeview",
                  background=[("selected", COLORS["accent"])],
                  foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading", background=[("active", COLORS["panel"])])
        style.configure("Vertical.TScrollbar", background=COLORS["panel"],
                        troughcolor=COLORS["bg"], borderwidth=0, arrowcolor=COLORS["muted"])
        style.configure("Horizontal.Progressbar", background=COLORS["accent"],
                        troughcolor=COLORS["panel"], borderwidth=0)

    # -- layout -------------------------------------------------------------
    def _build_ui(self):
        header = tk.Frame(self, bg=COLORS["bg"])
        header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(header, text=APP_NAME, font=("Segoe UI Semibold", 18),
                 bg=COLORS["bg"], fg=COLORS["text"]).pack(side="left")
        tk.Label(header, text=f"v{APP_VERSION}  •  {DEVELOPER}",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["muted"]).pack(side="left", padx=12, pady=(6, 0))

        toolbar = tk.Frame(self, bg=COLORS["bg"])
        toolbar.pack(fill="x", padx=20, pady=(0, 8))

        self.btn_refresh = self._button(toolbar, "Yenile", self.refresh_apps)
        self.btn_refresh.pack(side="left")
        self.btn_select_all = self._button(toolbar, "Kaldırılabilirleri seç", self.select_all_removable)
        self.btn_select_all.pack(side="left", padx=8)
        self.btn_clear = self._button(toolbar, "Seçimi temizle", self.clear_selection)
        self.btn_clear.pack(side="left")
        self.btn_remove = self._button(toolbar, "Seçilenleri kaldır", self.confirm_and_remove, danger=True)
        self.btn_remove.pack(side="right")

        search_frame = tk.Frame(self, bg=COLORS["bg"])
        search_frame.pack(fill="x", padx=20, pady=(0, 8))
        tk.Label(search_frame, text="Ara", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Segoe UI", 9)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.apply_filter())
        entry = tk.Entry(search_frame, textvariable=self.search_var, bg=COLORS["panel"],
                         fg=COLORS["text"], insertbackground=COLORS["text"],
                         relief="flat", font=("Segoe UI", 10))
        entry.pack(side="left", fill="x", expand=True, padx=8, ipady=4)

        table_frame = tk.Frame(self, bg=COLORS["bg"])
        table_frame.pack(fill="both", expand=True, padx=20)

        columns = ("name", "type", "protected")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                 selectmode="extended")
        self.tree.heading("name", text="Ad", anchor="w")
        self.tree.heading("type", text="Tür", anchor="w")
        self.tree.heading("protected", text="Korumalı", anchor="w")
        self.tree.column("name", width=520, anchor="w")
        self.tree.column("type", width=140, anchor="w")
        self.tree.column("protected", width=160, anchor="w")
        self.tree.tag_configure("protected", foreground=COLORS["danger"])
        self.tree.tag_configure("normal", foreground=COLORS["text"])

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", self._show_details)

        footer = tk.Frame(self, bg=COLORS["bg"])
        footer.pack(fill="x", padx=20, pady=12)
        self.status_var = tk.StringVar(value="Hazır")
        tk.Label(footer, textvariable=self.status_var, bg=COLORS["bg"],
                 fg=COLORS["muted"], font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(footer, mode="determinate", length=260)
        self.progress.pack(side="right")

    def _button(self, parent, text, command, danger=False):
        bg = COLORS["danger"] if danger else COLORS["accent"]
        hover = "#dc2626" if danger else COLORS["accent_hover"]
        btn = tk.Button(parent, text=text, command=command, bg=bg, fg="#ffffff",
                        activebackground=hover, activeforeground="#ffffff",
                        relief="flat", bd=0, padx=14, pady=6,
                        font=("Segoe UI Semibold", 9), cursor="hand2")
        return btn

    # -- state helpers ------------------------------------------------------
    def _set_busy(self, busy, message=None):
        self.busy = busy
        state = "disabled" if busy else "normal"
        for btn in (self.btn_refresh, self.btn_select_all, self.btn_clear, self.btn_remove):
            btn.configure(state=state)
        if message:
            self.status_var.set(message)
        if busy:
            self.configure(cursor="watch")
        else:
            self.configure(cursor="")

    def _set_progress(self, value, maximum=100):
        self.progress.configure(maximum=max(maximum, 1), value=value)

    # -- scanning -----------------------------------------------------------
    def refresh_apps(self):
        if self.busy:
            return
        self._set_busy(True, "Kurulu uygulamalar taranıyor…")
        self._set_progress(0, 100)
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)

        def worker():
            try:
                apps, errors = scan_all_apps()
                self.queue.put(("scan_done", apps, errors))
            except Exception as exc:
                self.queue.put(("error", f"Tarama başarısız: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def _populate(self, apps):
        self.apps = apps
        self.apply_filter()

    def apply_filter(self):
        query = self.search_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        self.item_map.clear()
        for app in self.apps:
            if query and query not in app["name"].lower() and query not in app["type"].lower():
                continue
            prot_text = "Evet" if app["protected"] else "Hayır"
            tag = "protected" if app["protected"] else "normal"
            iid = self.tree.insert("", "end", values=(app["name"], app["type"], prot_text), tags=(tag,))
            self.item_map[iid] = app
        self._update_status()

    def _update_status(self):
        total = len(self.apps)
        protected = sum(1 for a in self.apps if a["protected"])
        shown = len(self.item_map)
        self.status_var.set(
            f"{shown} gösteriliyor  •  {total} toplam  •  {protected} korumalı  •  "
            f"{len(self.tree.selection())} seçili"
        )

    # -- selection ----------------------------------------------------------
    def _on_select(self, _event=None):
        selected = self.tree.selection()
        for iid in selected:
            app = self.item_map.get(iid)
            if app and app["protected"]:
                self.tree.selection_remove(iid)
                self.bell()
        self._update_status()

    def select_all_removable(self):
        ids = [iid for iid, app in self.item_map.items() if not app["protected"]]
        self.tree.selection_set(ids)
        self._update_status()

    def clear_selection(self):
        self.tree.selection_remove(self.tree.selection())
        self._update_status()

    def _show_details(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        app = self.item_map.get(sel[0])
        if not app:
            return
        lines = [
            f"Ad: {app['name']}",
            f"Tür: {app['type']}",
            f"Yayımcı: {app['publisher'] or '—'}",
            f"Sürüm: {app['version'] or '—'}",
            f"Korumalı: {'Evet' if app['protected'] else 'Hayır'}",
        ]
        if app["protected"]:
            lines.append(f"Neden: {app['protect_reason']}")
        messagebox.showinfo("Uygulama ayrıntıları", "\n".join(lines), parent=self)

    # -- removal -----------------------------------------------------------
    def confirm_and_remove(self):
        if self.busy:
            return
        selected_ids = self.tree.selection()
        apps = [self.item_map[i] for i in selected_ids if i in self.item_map]

        if not apps:
            messagebox.showinfo(APP_NAME, "Hiçbir uygulama seçilmedi.", parent=self)
            return

        blocked = [a for a in apps if a["protected"]]
        apps = [a for a in apps if not a["protected"]]
        if blocked:
            messagebox.showwarning(
                APP_NAME,
                f"{len(blocked)} korumalı uygulama hariç tutuldu ve kaldırılmayacak.",
                parent=self,
            )
        if not apps:
            return

        names = "\n".join(f"  • {a['name']}" for a in apps[:20])
        if len(apps) > 20:
            names += f"\n  … and {len(apps) - 20} more"
        confirmed = messagebox.askyesno(
            "Kaldırmayı onayla",
            f"{len(apps)} uygulama kaldırılmak üzere:\n\n{names}\n\n"
            "Önce yedek klasörüne bir JSON günlüğü kaydedilecek.\n"
            "Bu işlem otomatik olarak geri alınamaz. Devam edilsin mi?",
            icon="warning",
            parent=self,
        )
        if not confirmed:
            return

        self._set_busy(True, "Uygulamalar kaldırılıyor…")
        self.progress.configure(mode="determinate")
        self._set_progress(0, len(apps))

        # Log is written BEFORE removal begins, with status "pending".
        pending = [{
            "name": a["name"], "type": a["type"], "id": a["id"],
            "publisher": a["publisher"], "version": a["version"],
            "status": "pending", "error": None,
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        } for a in apps]
        try:
            log_path = write_removal_log(pending)
        except Exception as exc:
            self._set_busy(False, "Hazır")
            messagebox.showerror(APP_NAME,
                                 f"Yedek günlüğü yazılamadı. Hiçbir uygulama kaldırılmadı.\n\n{exc}",
                                 parent=self)
            return

        def worker():
            try:
                def progress(done, total, name):
                    self.queue.put(("progress", done, total, name))
                results = remove_apps(apps, progress_cb=progress)
                final_path = write_removal_log(results)
                self.queue.put(("remove_done", results, log_path, final_path))
            except Exception as exc:
                self.queue.put(("error", f"Kaldırma başarısız: {exc}"))

        threading.Thread(target=worker, daemon=True).start()

    # -- queue polling ------------------------------------------------------
    def _poll_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                kind = msg[0]
                if kind == "scan_done":
                    _, apps, errors = msg
                    self.progress.stop()
                    self.progress.configure(mode="determinate")
                    self._set_progress(0, 100)
                    self._set_busy(False)
                    self._populate(apps)
                    if errors:
                        messagebox.showwarning(APP_NAME, "\n".join(errors), parent=self)
                elif kind == "progress":
                    _, done, total, name = msg
                    self._set_progress(done, total)
                    self.status_var.set(f"Kaldırılıyor {done}/{total}: {name}")
                elif kind == "remove_done":
                    _, results, log_path, final_path = msg
                    self._set_busy(False)
                    self._set_progress(0, 100)
                    self._handle_results(results, log_path, final_path)
                    self.refresh_apps()
                elif kind == "error":
                    self.progress.stop()
                    self.progress.configure(mode="determinate")
                    self._set_busy(False, "Hata")
                    messagebox.showerror(APP_NAME, msg[1], parent=self)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_results(self, results, log_path, final_path):
        ok = [r for r in results if r["status"] == "removed"]
        failed = [r for r in results if r["status"] == "failed"]
        skipped = [r for r in results if r["status"] == "skipped_protected"]

        self.status_var.set(f"Tamamlandı: {len(ok)} kaldırıldı, {len(failed)} başarısız, {len(skipped)} atlandı")

        summary = [
            f"Kaldırılan: {len(ok)}",
            f"Başarısız: {len(failed)}",
            f"Atlanan (korumalı): {len(skipped)}",
            "",
            f"Günlük kaydedildi:\n{final_path}",
        ]
        if failed:
            details = "\n".join(f"• {r['name']}: {r['error']}" for r in failed[:10])
            summary.append("\nBaşarısız olanlar:\n" + details)
            messagebox.showwarning(APP_NAME, "\n".join(summary), parent=self)
        else:
            messagebox.showinfo(APP_NAME, "\n".join(summary), parent=self)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    ensure_windows()
    app = ReclaimerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
