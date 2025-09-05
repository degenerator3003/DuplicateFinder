#!/usr/bin/env python3
"""
Duplicate Finder GUI (Tkinter, stdlib-only)
Python 3.10+

Two-stage duplicate detection:
- Size match → head+tail fingerprint (BLAKE2b-128) → full-file BLAKE2b-256 (16 MB chunks), with up to 4 worker threads.

UI features:
- Multiple sources, excluded folders, include/exclude patterns, minimum size filter.
- Tree of groups: original (oldest mtime) with duplicate children; group numbers shown.
- Per-group “Dup Size (group)” and click-to-sort by duplicate bytes.
- Red “Total dup size” label that updates as results change.
- Quarantine meters: green baseline (size when chosen) and blue “Added since selection” values.
- Actions: Open, Reveal in Folder, Copy Paths, Select Duplicates in Group, Select Duplicates (All Groups),
  Promote to Primary, Toggle Flag on Selection, Move to Quarantine, Delete Selected/Flagged…, Export CSV.

Implementation notes:
- Background worker thread; UI updates via a queue; cancellation via an event.
- Cross-device-safe quarantine move (copy-then-delete fallback).
"""

from __future__ import annotations

import os
import sys
import csv
import queue
import errno
import shutil
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple, Iterable, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ----------------------------- Constants -----------------------------

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB
FP_BYTES = 64 * 1024           # 64 KB head and tail
FLAG_ON  = "\u2611"  # "[x]"
FLAG_OFF = "\u2610"  # "[ ]"

# ----------------------------- Helpers -----------------------------

def human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    units = ["KB", "MB", "GB", "TB", "PB"]
    v = float(n)
    for u in units:
        v /= 1024.0
        if v < 1024.0:
            return f"{v:.2f} {u}"
    return f"{v:.2f} EB"


def blake2b_256_of(path: Path, stop: threading.Event) -> Optional[str]:
    h = hashlib.blake2b(digest_size=32)
    try:
        with path.open("rb") as f:
            while True:
                if stop.is_set():
                    return None
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return "__ERROR__"


def quick_fingerprint(path: Path, stop: threading.Event, bytes_per_end: int = FP_BYTES) -> Optional[str]:
    try:
        st = path.stat()
        sz = int(st.st_size)
        h = hashlib.blake2b(digest_size=16)
        with path.open("rb") as f:
            n = min(bytes_per_end, sz)
            if n > 0:
                if stop.is_set():
                    return None
                h.update(f.read(n))              # head
                if stop.is_set():
                    return None
                if sz > n:
                    f.seek(max(0, sz - n))
                    h.update(f.read(n))          # tail
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return "__ERROR__"


def reveal_in_file_manager(path: Path) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(path if path.is_dir() else path.parent)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            import subprocess
            if path.is_dir():
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["open", "-R", str(path)])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", str(path if path.is_dir() else path.parent)])
    except Exception as e:
        messagebox.showerror("Open Error", f"Could not open file manager: {e}")

# ----------------------------- Data classes -----------------------------

@dataclass
class ScanOptions:
    roots: List[Path]
    include_subdirs: bool = True
    follow_symlinks: bool = False
    min_size: int = 1
    include_patterns: Optional[str] = None
    exclude_patterns: Optional[str] = None
    quarantine_dir: Optional[Path] = None
    exclude_dirs: List[Path] = field(default_factory=list)


@dataclass
class Progress:
    stage: str
    current: int
    total: int
    bytes_done: int = 0
    bytes_total: int = 0
    files_hashed: int = 0
    files_skipped: int = 0
    errors: int = 0


@dataclass
class Group:
    digest: str
    size: int
    files: List[Path]

# ----------------------------- Worker -----------------------------

class DuplicateWorker:
    def __init__(self, options: ScanOptions, q_out: queue.Queue, stop: threading.Event):
        self.options = options
        self.q_out = q_out
        self.stop = stop
        self.errors = 0

    def _iter_files(self) -> Iterable[Path]:
        opts = self.options
        include_globs = [p.strip() for p in (opts.include_patterns or "").split(";") if p.strip()]
        exclude_globs = [p.strip() for p in (opts.exclude_patterns or "").split(";") if p.strip()]

        seen: set[Tuple[int, int]] = set()  # (st_dev, st_ino)

        # normalize excluded roots
        ex_roots: List[str] = []
        for er in (opts.exclude_dirs or []):
            try:
                ex_roots.append(os.path.normcase(os.path.abspath(str(er))))
            except Exception:
                continue

        def is_excluded(p: Path | str) -> bool:
            try:
                sp = os.path.normcase(os.path.abspath(str(p)))
                for er in ex_roots:
                    try:
                        if os.path.commonpath([sp, er]) == er:
                            return True
                    except Exception:
                        continue
                return False
            except Exception:
                return False

        def want(path: Path) -> bool:
            try:
                if is_excluded(path):
                    return False
                st = path.stat()
            except (PermissionError, FileNotFoundError, OSError):
                self.errors += 1
                return False
            if not path.is_file():
                return False
            if st.st_size < opts.min_size:
                return False
            if include_globs and not any(path.match(g) for g in include_globs):
                return False
            if exclude_globs and any(path.match(g) for g in exclude_globs):
                return False
            try:
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    return False
                seen.add(key)
            except Exception:
                pass
            return True

        for root in opts.roots:
            if self.stop.is_set():
                return
            try:
                if is_excluded(root):
                    continue
                if not root.exists():
                    continue
                if root.is_file():
                    if want(root):
                        yield root
                    continue
                if opts.include_subdirs:
                    for dirpath, dirnames, filenames in os.walk(root, followlinks=opts.follow_symlinks):
                        if self.stop.is_set():
                            return
                        # prune excluded subdirs
                        for i in range(len(dirnames) - 1, -1, -1):
                            sub = Path(dirpath) / dirnames[i]
                            if is_excluded(sub):
                                del dirnames[i]
                        dirpath_p = Path(dirpath)
                        for name in filenames:
                            p = dirpath_p / name
                            if want(p):
                                yield p
                else:
                    for p in root.iterdir():
                        if self.stop.is_set():
                            return
                        if p.is_file() and want(p):
                            yield p
            except Exception:
                self.errors += 1
                continue

    def run(self) -> None:
        # Stage A: counting
        files: List[Path] = []
        bytes_total = 0
        for p in self._iter_files():
            if self.stop.is_set():
                return
            try:
                st = p.stat()
                files.append(p)
                bytes_total += int(st.st_size)
                if len(files) % 256 == 0:
                    self.q_out.put(Progress("counting", len(files), 0, bytes_total, bytes_total, 0, 0, self.errors))
            except Exception:
                self.errors += 1
        self.q_out.put(Progress("counting", len(files), len(files), bytes_total, bytes_total, 0, 0, self.errors))
        if self.stop.is_set():
            return

        # Stage B: size buckets
        size_map: Dict[int, List[Path]] = {}
        for p in files:
            try:
                sz = int(p.stat().st_size)
            except Exception:
                self.errors += 1
                continue
            size_map.setdefault(sz, []).append(p)
        candidates = [(sz, lst) for sz, lst in size_map.items() if len(lst) > 1]
        candidates.sort(key=lambda t: t[0], reverse=True)

        # Stage B2: fingerprint
        fp_total = sum(len(lst) for _, lst in candidates)
        fp_done = 0
        fp_groups: Dict[Tuple[int, str], List[Path]] = {}
        for sz, lst in candidates:
            if self.stop.is_set():
                return
            for p in lst:
                if self.stop.is_set():
                    return
                fp = quick_fingerprint(p, self.stop, FP_BYTES)
                if fp is None:
                    return
                if fp == "__ERROR__":
                    self.errors += 1
                    continue
                fp_groups.setdefault((sz, fp), []).append(p)
                fp_done += 1
                if fp_done % 64 == 0 or fp_done == fp_total:
                    self.q_out.put(Progress("fingerprinting", fp_done, fp_total, 0, 0, 0, 0, self.errors))

        # Full hashes list (only where collisions remain)
        full_list: List[Tuple[int, Path]] = []
        for (sz, _fp), paths in fp_groups.items():
            if len(paths) > 1:
                for p in paths:
                    full_list.append((sz, p))

        hash_file_total = len(full_list)
        hash_bytes_total = sum(sz for sz, _ in full_list)
        files_hashed = 0
        bytes_done = 0
        digest_map: Dict[Tuple[int, str], List[Path]] = {}

        # Stage C: full hashing, modest parallelism
        max_workers = min(4, (os.cpu_count() or 2))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(blake2b_256_of, p, self.stop): (sz, p) for sz, p in full_list}
            for fut in as_completed(futures):
                if self.stop.is_set():
                    return
                sz, p = futures[fut]
                try:
                    digest = fut.result()
                except Exception:
                    digest = "__ERROR__"
                if digest is None:
                    return
                if digest == "__ERROR__":
                    self.errors += 1
                    continue
                digest_map.setdefault((sz, digest), []).append(p)
                files_hashed += 1
                bytes_done += sz
                if files_hashed % 16 == 0 or files_hashed == hash_file_total:
                    self.q_out.put(Progress("hashing", files_hashed, hash_file_total, bytes_done, hash_bytes_total, files_hashed, 0, self.errors))

        # Stage D: build groups
        groups: List[Group] = []
        for (sz, dg), paths in digest_map.items():
            if len(paths) > 1:
                groups.append(Group(digest=dg, size=sz, files=sorted(paths)))

        result: List[Tuple[Path, List[Path], int, str]] = []
        for g in groups:
            try:
                orig = min(g.files, key=lambda p: p.stat().st_mtime)
            except Exception:
                orig = g.files[0]
            dups = [p for p in g.files if p != orig]
            result.append((orig, dups, g.size, g.digest))

        self.q_out.put(("RESULTS", result))
        self.q_out.put(Progress("done", 1, 1, bytes_done, hash_bytes_total, files_hashed, 0, self.errors))

# ----------------------------- GUI -----------------------------

class DuplicateFinderApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Duplicate Finder")
        self.geometry("1260x820")
        self.minsize(980, 620)

        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None

        # quarantine meters state
        self.q_baseline_bytes = 0
        self.q_added_bytes = 0
        self.sort_dupsize_desc = True

        self._build_ui()
        self._configure_style()
        self.after(100, self._poll_queue)

    def _build_ui(self) -> None:
        # Sources frame
        src_frame = ttk.LabelFrame(self, text="Sources")
        src_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        left = ttk.Frame(src_frame); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(left, text="Included folders").pack(anchor="w", padx=(10,5), pady=(10,0))
        self.src_list = tk.Listbox(left, height=4, selectmode=tk.EXTENDED)
        self.src_list.pack(fill=tk.BOTH, expand=True, padx=(10,5), pady=(0,10))
        btns = ttk.Frame(src_frame); btns.pack(side=tk.LEFT, fill=tk.Y, padx=(5,10), pady=10)
        ttk.Button(btns, text="Add Folder…", command=self.on_add_folder).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="Remove Selected", command=self.on_remove_selected).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="Clear", command=self.on_clear_sources).pack(fill=tk.X, pady=2)

        right = ttk.Frame(src_frame); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Label(right, text="Excluded folders").pack(anchor="w", padx=(10,5), pady=(10,0))
        self.excl_list = tk.Listbox(right, height=4, selectmode=tk.EXTENDED)
        self.excl_list.pack(fill=tk.BOTH, expand=True, padx=(10,5), pady=(0,10))
        exbtns = ttk.Frame(src_frame); exbtns.pack(side=tk.LEFT, fill=tk.Y, padx=(5,10), pady=10)
        ttk.Button(exbtns, text="Add Excluded…", command=self.on_add_excluded_folder).pack(fill=tk.X, pady=2)
        ttk.Button(exbtns, text="Remove Selected", command=self.on_remove_selected_excluded).pack(fill=tk.X, pady=2)
        ttk.Button(exbtns, text="Clear", command=self.on_clear_excluded).pack(fill=tk.X, pady=2)

        opts = ttk.Frame(src_frame); opts.pack(side=tk.RIGHT, fill=tk.X, padx=10, pady=10)
        self.var_subdirs = tk.BooleanVar(value=True)
        self.var_symlinks = tk.BooleanVar(value=False)
        self.var_min_size = tk.StringVar(value="1")
        self.var_incl = tk.StringVar(value="")
        self.var_excl = tk.StringVar(value="")
        self.var_quarantine = tk.StringVar(value="")
        for row, (lbl, widget) in enumerate([
            ("Include subfolders", ttk.Checkbutton(opts, variable=self.var_subdirs)),
            ("Follow symlinks", ttk.Checkbutton(opts, variable=self.var_symlinks)),
            ("Min size (bytes)", ttk.Entry(opts, textvariable=self.var_min_size, width=12)),
            ("Include patterns (*.jpg;*.png)", ttk.Entry(opts, textvariable=self.var_incl, width=30)),
            ("Exclude patterns (*.tmp;*.bak)", ttk.Entry(opts, textvariable=self.var_excl, width=30)),
        ]):
            ttk.Label(opts, text=lbl).grid(row=row, column=0, sticky="w", padx=5, pady=2)
            widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)

        # Quarantine block
        qblock = ttk.LabelFrame(opts, text="Quarantine")
        qblock.grid(row=5, column=0, columnspan=3, sticky="ew", padx=5, pady=(8,2))
        qblock.columnconfigure(0, weight=1)
        self.q_base_var = tk.StringVar(value="Baseline size: 0 B (0 bytes)")
        self.q_added_var = tk.StringVar(value="Added since selection: 0 B (0 bytes)")
        ttk.Label(qblock, textvariable=self.q_base_var, foreground="green").pack(anchor="w", padx=6, pady=(6,2))
        ttk.Label(qblock, textvariable=self.q_added_var, foreground="#0b5394").pack(anchor="w", padx=6, pady=(0,6))
        qrow = ttk.Frame(qblock); qrow.pack(fill="x", padx=6, pady=(0,8))
        ttk.Entry(qrow, textvariable=self.var_quarantine, width=40).pack(side=tk.LEFT, fill="x", expand=True)
        ttk.Button(qrow, text="Choose…", command=self.on_choose_quarantine).pack(side=tk.LEFT, padx=6)

        # Controls + progress
        ctrl = ttk.Frame(self); ctrl.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0,10))
        self.btn_start = ttk.Button(ctrl, text="Start", command=self.on_start)
        self.btn_stop = ttk.Button(ctrl, text="Stop", command=self.on_stop, state=tk.DISABLED)
        self.btn_export = ttk.Button(ctrl, text="Export CSV", command=self.on_export, state=tk.DISABLED)
        self.btn_start.pack(side=tk.LEFT, padx=5); self.btn_stop.pack(side=tk.LEFT, padx=5); self.btn_export.pack(side=tk.LEFT, padx=5)
        self.progress = ttk.Progressbar(ctrl, length=320, mode="determinate"); self.progress.pack(side=tk.LEFT, padx=15)
        self.status = ttk.Label(ctrl, text="Idle"); self.status.pack(side=tk.LEFT, padx=10)
        # Dynamic total duplicates label (red)
        self.total_var = tk.StringVar(value="Total dup size: 0 B (0 bytes); files: 0")
        self.total_label = tk.Label(ctrl, textvariable=self.total_var, fg="red")
        self.total_label.pack(side=tk.LEFT, padx=10)

        # Results
        bottom = ttk.Panedwindow(self, orient=tk.VERTICAL); bottom.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        tree_frame = ttk.Frame(bottom)
        # add hidden numeric columns: sizeb (file size), dupszb (group dup bytes)
        self.tree = ttk.Treeview(tree_frame, columns=("grp","flag","size","dupsize","hash","sizeb","dupsizeb"), show="tree headings")
        self.tree.heading("#0", text="Path"); self.tree.column("#0", width=760, anchor="w")
        self.tree.heading("grp", text="Group"); self.tree.column("grp", width=70, anchor="center")
        self.tree.heading("flag", text="Flag"); self.tree.column("flag", width=60, anchor="center")
        self.tree.heading("size", text="Size"); self.tree.column("size", width=120, anchor="e")
        # clickable header to sort by dup size
        self.tree.heading("dupsize", text="Dup Size (group)", command=self.on_sort_dupsize)
        self.tree.column("dupsize", width=200, anchor="e")
        self.tree.heading("hash", text="Hash (BLAKE2b-256)"); self.tree.column("hash", width=280, anchor="w")
        # hide numeric columns
        self.tree.column("sizeb", width=0, minwidth=0, stretch=False)
        self.tree.column("dupsizeb", width=0, minwidth=0, stretch=False)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew"); vsb.grid(row=0, column=1, sticky="ns"); hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1); tree_frame.columnconfigure(0, weight=1)

        self.tree.bind("<Button-1>", self._on_tree_click)   # toggle flag cell (still works)
        self.tree.bind("<space>", self.on_toggle_flag_on_selection)

        action_frame = ttk.Frame(bottom)
        for txt, cmd in [
            ("Open", self.on_open_file),
            ("Reveal in folder", self.on_reveal),
            ("Copy paths", self.on_copy_paths),
            ("Select duplicates in group", self.on_select_group_dups),
            ("Promote to primary", self.on_promote_to_primary),
            ("Toggle flag on selection", self.on_toggle_flag_on_selection),
            ("Delete Selected/Flagged…", self.on_delete_selected),
            ("Select duplicates (all groups)", self.on_select_all_duplicates),
            ("Move selected/flagged to quarantine", self.on_move_selected),
        ]:
            ttk.Button(action_frame, text=txt, command=cmd).pack(side=tk.LEFT, padx=5, pady=5)

        bottom.add(tree_frame, weight=4); bottom.add(action_frame, weight=0)

    def _configure_style(self) -> None:
        ttk.Style(self)
        self.tree.tag_configure("original", background="")
        self.tree.tag_configure("duplicate", background="")

    # ---- Source controls ----
    def on_add_folder(self) -> None:
        path = filedialog.askdirectory(title="Choose folder to scan")
        if path:
            self.src_list.insert(tk.END, path)

    def on_remove_selected(self) -> None:
        sel = list(self.src_list.curselection())
        for idx in reversed(sel):
            self.src_list.delete(idx)
        self._filter_results_to_sources()

    def on_clear_sources(self) -> None:
        self.src_list.delete(0, tk.END)
        self._clear_results()
        self.status.configure(text="Sources cleared. Previous results removed.")
        self.btn_export.configure(state=tk.DISABLED)

    def on_add_excluded_folder(self) -> None:
        path = filedialog.askdirectory(title="Choose folder to exclude")
        if path:
            self.excl_list.insert(tk.END, path)

    def on_remove_selected_excluded(self) -> None:
        sel = list(self.excl_list.curselection())
        for idx in reversed(sel):
            self.excl_list.delete(idx)
        self._filter_results_to_sources()

    def on_clear_excluded(self) -> None:
        self.excl_list.delete(0, tk.END)
        self._filter_results_to_sources()

    def on_choose_quarantine(self) -> None:
        path = filedialog.askdirectory(title="Choose quarantine folder")
        if not path:
            return
        self.var_quarantine.set(path)
        # compute baseline and reset session-added
        try:
            self.q_baseline_bytes = self._folder_size_bytes(Path(path))
        except Exception:
            self.q_baseline_bytes = 0
        self.q_added_bytes = 0
        self._update_quarantine_labels()

    # ---- Start/Stop ----
    def on_start(self) -> None:
        roots = [Path(self.src_list.get(i)) for i in range(self.src_list.size())]
        if not roots:
            messagebox.showwarning("No sources", "Add at least one folder or drive root to scan.")
            return
        try:
            min_size = int(self.var_min_size.get().strip() or "1")
            if min_size < 1:
                min_size = 1
        except ValueError:
            messagebox.showerror("Invalid size", "Min size must be an integer number of bytes.")
            return
        quarantine = Path(self.var_quarantine.get().strip()) if self.var_quarantine.get().strip() else None
        if quarantine is not None:
            try:
                quarantine.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("Quarantine error", f"Cannot create/access quarantine folder: {e}")
                return
        exclude_dirs = [Path(self.excl_list.get(i)) for i in range(self.excl_list.size())]

        options = ScanOptions(
            roots=roots,
            include_subdirs=self.var_subdirs.get(),
            follow_symlinks=self.var_symlinks.get(),
            min_size=min_size,
            include_patterns=self.var_incl.get().strip() or None,
            exclude_patterns=self.var_excl.get().strip() or None,
            quarantine_dir=quarantine,
            exclude_dirs=exclude_dirs,
        )

        self._clear_results()
        self.progress.configure(value=0, maximum=100)
        self.status.configure(text="Counting files…")
        self.total_var.set("Total dup size: 0 B (0 bytes); files: 0")
        # session-added resets on Start
        self.q_added_bytes = 0
        self._update_quarantine_labels()

        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.btn_export.configure(state=tk.DISABLED)
        self.stop_event.clear()

        worker = DuplicateWorker(options, self.queue, self.stop_event)
        t = threading.Thread(target=worker.run, daemon=True)
        self.worker_thread = t
        t.start()

    def on_stop(self) -> None:
        self.stop_event.set()
        self.btn_stop.configure(state=tk.DISABLED)
        self.status.configure(text="Stopping…")

    # ---- Queue polling ----
    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self.queue.get_nowait()
                if isinstance(msg, Progress):
                    self._handle_progress(msg)
                elif isinstance(msg, tuple) and msg and msg[0] == "RESULTS":
                    self._handle_results(msg[1])
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_queue)

    def _handle_progress(self, p: Progress) -> None:
        if p.stage == "counting":
            self.progress.configure(mode="indeterminate")
            self.progress.start(10)
            self.status.configure(text=f"Counting… Files: {p.current}  Errors: {p.errors}")
        elif p.stage == "fingerprinting":
            self.progress.stop(); self.progress.configure(mode="determinate")
            total = p.total or 1
            self.progress.configure(value=int((p.current/total)*100), maximum=100)
            self.status.configure(text=f"Fingerprinting {p.current}/{p.total}… Errors: {p.errors}")
        elif p.stage == "hashing":
            self.progress.stop(); self.progress.configure(mode="determinate")
            total = p.total or 1
            self.progress.configure(value=int((p.current/total)*100), maximum=100)
            self.status.configure(text=(
                f"Hashing {p.current}/{p.total} files…  "
                f"Bytes: {human_bytes(p.bytes_done)}/{human_bytes(p.bytes_total)}  "
                f"Errors: {p.errors}"
            ))
        elif p.stage == "done":
            self.progress.stop(); self.progress.configure(mode="determinate", value=100)
            self.status.configure(text=f"Done. Hashed {p.files_hashed} files. Errors: {p.errors}")
            self.btn_start.configure(state=tk.NORMAL)
            self.btn_stop.configure(state=tk.DISABLED)
            self.btn_export.configure(state=tk.NORMAL if len(self.tree.get_children()) else tk.DISABLED)

    # ---- Totals / Quarantine meters helpers ----
    def _update_totals_from_tree(self) -> None:
        total_bytes = 0
        total_files = 0
        for parent in self.tree.get_children(""):
            try:
                sizeb = int(self.tree.set(parent, "sizeb") or 0)
            except Exception:
                sizeb = 0
            dup_count = len(self.tree.get_children(parent))
            total_files += dup_count
            total_bytes += sizeb * dup_count
        self.total_var.set(
            f"Total dup size: {human_bytes(total_bytes)} ({total_bytes} bytes); files: {total_files}"
        )
        self.btn_export.configure(state=tk.NORMAL if len(self.tree.get_children("")) else tk.DISABLED)

    def _recompute_group_dupsizes(self) -> None:
        for parent in self.tree.get_children(""):
            try:
                sizeb = int(self.tree.set(parent, "sizeb") or 0)
            except Exception:
                sizeb = 0
            dup_count = len(self.tree.get_children(parent))
            dup_bytes = sizeb * dup_count
            dup_size_str = f"{human_bytes(dup_bytes)} ({dup_bytes} bytes)" if dup_count else ""
            self.tree.set(parent, "dupsize", dup_size_str)
            self.tree.set(parent, "dupsizeb", str(dup_bytes))

    def _update_quarantine_labels(self) -> None:
        self.q_base_var.set(
            f"Baseline size: {human_bytes(self.q_baseline_bytes)} ({self.q_baseline_bytes} bytes)"
        )
        self.q_added_var.set(
            f"Adding since selection: {human_bytes(self.q_added_bytes)} ({self.q_added_bytes} bytes)"
        )

    def _folder_size_bytes(self, root: Path) -> int:
        total = 0
        try:
            for dirpath, _dirnames, filenames in os.walk(root):
                for name in filenames:
                    try:
                        total += (Path(dirpath) / name).stat().st_size
                    except Exception:
                        pass
        except Exception:
            pass
        return total

    # ---- Results ----
    def _clear_results(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.total_var.set("Total dup size: 0 B (0 bytes); files: 0")

    def _handle_results(self, results: List[Tuple[Path, List[Path], int, str]]) -> None:
        for idx, (orig, dups, size, digest) in enumerate(
            sorted(results, key=lambda t: (t[2], str(t[0]).lower()), reverse=True), start=1
        ):
            dup_count = len(dups)
            dup_bytes = size * dup_count
            dup_size_str = f"{human_bytes(dup_bytes)} ({dup_bytes} bytes)" if dup_count else ""
            parent = self.tree.insert(
                "", tk.END,
                text=str(orig),
                values=(str(idx), FLAG_OFF, human_bytes(size), dup_size_str, digest, str(size), str(dup_bytes)),
                tags=("original",)
            )
            for dup in dups:
                self.tree.insert(
                    parent, tk.END,
                    text=str(dup),
                    values=(str(idx), FLAG_OFF, human_bytes(size), "", digest, str(size), "0"),
                    tags=("duplicate",)
                )
        for item in self.tree.get_children():
            self.tree.item(item, open=True)
        self._recompute_group_dupsizes()
        self._update_totals_from_tree()
        if results:
            self.status.configure(text=f"Found {len(results)} duplicate sets.")
        else:
            self.status.configure(text="No duplicate sets found.")

    # ---- Actions ----
    def _flagged_items(self) -> List[str]:
        items: List[str] = []
        for parent in self.tree.get_children(""):
            if self.tree.set(parent, "flag") == FLAG_ON:
                items.append(parent)
            for child in self.tree.get_children(parent):
                if self.tree.set(child, "flag") == FLAG_ON:
                    items.append(child)
        return items

    def _items_to_paths(self, items: List[str]) -> List[Path]:
        return [Path(self.tree.item(it, "text")) for it in items]

    def _active_items(self) -> List[str]:
        flagged = self._flagged_items()
        return flagged if flagged else list(self.tree.selection())

    def _active_paths(self) -> List[Path]:
        return self._items_to_paths(self._active_items())

    def on_open_file(self) -> None:
        for p in self._active_paths():
            try:
                if sys.platform.startswith("win"):
                    os.startfile(p)  # type: ignore[attr-defined]
                elif sys.platform == "darwin":
                    import subprocess; subprocess.Popen(["open", str(p)])
                else:
                    import subprocess; subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                messagebox.showerror("Open Error", f"Could not open {p}: {e}")

    def on_reveal(self) -> None:
        for p in self._active_paths():
            reveal_in_file_manager(p)

    def on_copy_paths(self) -> None:
        paths = [str(p) for p in self._active_paths()]
        if not paths:
            return
        self.clipboard_clear(); self.clipboard_append("\n".join(paths))
        self.status.configure(text=f"Copied {len(paths)} path(s) to clipboard.")

    def on_select_group_dups(self) -> None:
        item = self.tree.focus() or (self.tree.selection()[0] if self.tree.selection() else None)
        if not item:
            return
        parent = self.tree.parent(item)
        group_root = parent or item
        children = self.tree.get_children(group_root)
        if not children:
            return
        self.tree.selection_set(children)

    def on_promote_to_primary(self) -> None:
        item = self.tree.focus() or (self.tree.selection()[0] if self.tree.selection() else None)
        if not item:
            messagebox.showinfo("Promote", "Select a duplicate row to promote.")
            return
        parent = self.tree.parent(item)
        if not parent:
            return  # already a parent
        # swap displayed paths between parent and child
        parent_text = self.tree.item(parent, "text")
        child_text = self.tree.item(item, "text")
        self.tree.item(parent, text=child_text)
        self.tree.item(item, text=parent_text)
        # swap flags so they follow the path
        pf, cf = self.tree.set(parent, "flag"), self.tree.set(item, "flag")
        self.tree.set(parent, "flag", cf)
        self.tree.set(item, "flag", pf)
        # focus
        self.tree.selection_set(parent); self.tree.focus(parent)
        self.status.configure(text="Promoted selected duplicate to primary for this group.")

    def on_toggle_flag_on_selection(self, event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        for item in sel:
            current = self.tree.set(item, "flag")
            self.tree.set(item, "flag", FLAG_OFF if current == FLAG_ON else FLAG_ON)
        self.status.configure(text=f"Toggled flag on {len(sel)} item(s)")

    def _on_tree_click(self, event) -> None:
        # Toggle checkbox when clicking in Flag column cells only
        if self.tree.identify("region", event.x, event.y) != "cell":
            return
        col = self.tree.identify_column(event.x)
        if col != "#2":  # #0=tree, #1=grp, #2=flag
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        current = self.tree.set(item, "flag")
        self.tree.set(item, "flag", FLAG_OFF if current == FLAG_ON else FLAG_ON)

    def on_sort_dupsize(self) -> None:
        # Sort only top-level groups by numeric 'dupsizeb'
        parents = list(self.tree.get_children(""))
        try:
            keyed = [(int(self.tree.set(p, "dupsizeb") or 0), p) for p in parents]
        except Exception:
            keyed = [(0, p) for p in parents]
        keyed.sort(key=lambda t: t[0], reverse=self.sort_dupsize_desc)
        for idx, (_k, p) in enumerate(keyed):
            self.tree.move(p, "", idx)
        self.sort_dupsize_desc = not self.sort_dupsize_desc

    def on_delete_selected(self) -> None:
        items = self._active_items()
        paths = [p for p in self._items_to_paths(items) if p.exists()]
        if not paths:
            messagebox.showinfo("Delete", "No existing files selected.")
            return
        if not messagebox.askyesno("Delete Selected", f"Permanently delete {len(paths)} file(s)? This cannot be undone."):
            return
        deleted = 0; errors = 0
        for p in paths:
            try:
                p.unlink(missing_ok=True)
                deleted += 1
            except Exception:
                errors += 1
        self.status.configure(text=f"Deleted {deleted} file(s). Errors: {errors}")
        self._prune_missing_tree_items()

    def on_select_all_duplicates(self) -> None:
        """Clear any current selection, then select all duplicate rows in every group."""
        # 1) clear any existing selection
        self.tree.selection_remove(self.tree.selection())

        # 2) select only children (duplicates) for every top-level group
        any_selected = False
        for parent in self.tree.get_children(""):
            children = self.tree.get_children(parent)
            if children:
                self.tree.selection_add(children)
                any_selected = True

        # 3) status message (optional)
        if any_selected:
            self.status.configure(text="Selected duplicates in all groups.")
        else:
            self.status.configure(text="No duplicates to select.")


    def on_move_selected(self) -> None:
        qdir_str = self.var_quarantine.get().strip()
        if not qdir_str:
            messagebox.showwarning("Quarantine not set", "Choose a quarantine folder in Sources first.")
            return
        qdir = Path(qdir_str)
        if not qdir.exists():
            try:
                qdir.mkdir(parents=True)
            except Exception as e:
                messagebox.showerror("Quarantine error", f"Cannot create quarantine folder: {e}")
                return
        items = self._active_items()
        if not items:
            messagebox.showinfo("Move", "No selected rows.")
            return
        paths = [Path(self.tree.item(it, "text")) for it in items if Path(self.tree.item(it, "text")).exists()]
        if not paths:
            messagebox.showinfo("Move", "No existing files selected.")
            return
        moved = 0; errors = 0; moved_bytes = 0
        for p in paths:
            try:
                sz = p.stat().st_size
            except Exception:
                sz = 0
            try:
                target = qdir / p.name
                base = target; i = 1
                while target.exists():
                    target = base.with_name(f"{base.stem} ({i}){base.suffix}"); i += 1
                try:
                    p.replace(target)
                except OSError as e:
                    if getattr(e, 'errno', None) == errno.EXDEV:
                        shutil.copy2(p, target); p.unlink()
                    else:
                        raise
                moved += 1
                moved_bytes += sz
            except Exception:
                errors += 1
        # update session-added meter
        self.q_added_bytes += moved_bytes
        self._update_quarantine_labels()

        self.status.configure(text=f"Moved {moved} file(s) to quarantine. Errors: {errors}")
        self._prune_missing_tree_items()

    # ---- Prune tree after file ops ----
    def _prune_missing_tree_items(self) -> None:
        to_delete: List[str] = []
        for parent in self.tree.get_children(""):
            parent_path = Path(self.tree.item(parent, "text"))
            if not parent_path.exists():
                to_delete.append(parent); continue
            for child in self.tree.get_children(parent):
                if not Path(self.tree.item(child, "text")).exists():
                    to_delete.append(child)
            remaining_children = [c for c in self.tree.get_children(parent) if c not in to_delete]
            if not remaining_children:
                to_delete.append(parent)
        # delete deepest-first
        def depth(it: str) -> int:
            d = 0; cur = it
            while True:
                par = self.tree.parent(cur)
                if not par: break
                d += 1; cur = par
            return d
        for item in sorted(set(to_delete), key=depth, reverse=True):
            try:
                if getattr(self.tree, "exists", None) and not self.tree.exists(item):
                    continue
                self.tree.delete(item)
            except Exception:
                pass
        # after pruning, recompute per-group dup sizes + totals
        self._recompute_group_dupsizes()
        self._update_totals_from_tree()

    # ---- Filter results to current sources ----
    def _current_roots(self) -> List[Path]:
        return [Path(self.src_list.get(i)) for i in range(self.src_list.size())]

    def _is_under_any_root(self, p: Path, roots: List[Path]) -> bool:
        sp = os.path.normcase(str(p))
        for r in roots:
            try:
                if os.path.commonpath([sp, os.path.normcase(str(r))]) == os.path.normcase(str(r)):
                    return True
            except Exception:
                continue
        return False

    def _filter_results_to_sources(self) -> None:
        roots = self._current_roots()
        if not roots:
            self._clear_results(); self.status.configure(text="All sources removed — cleared results."); self.btn_export.configure(state=tk.DISABLED); return
        to_delete: List[str] = []
        for parent in self.tree.get_children(""):
            p_path = Path(self.tree.item(parent, "text"))
            if not self._is_under_any_root(p_path, roots):
                to_delete.append(parent); continue
            for child in self.tree.get_children(parent):
                c_path = Path(self.tree.item(child, "text"))
                if not self._is_under_any_root(c_path, roots):
                    to_delete.append(child)
            remaining = [c for c in self.tree.get_children(parent) if c not in to_delete]
            if not remaining:
                to_delete.append(parent)
        # delete deepest-first
        def depth2(it: str) -> int:
            d = 0; cur = it
            while True:
                par = self.tree.parent(cur)
                if not par: break
                d += 1; cur = par
            return d
        for item in sorted(set(to_delete), key=depth2, reverse=True):
            try:
                if getattr(self.tree, "exists", None) and not self.tree.exists(item):
                    continue
                self.tree.delete(item)
            except Exception:
                pass
        # after filtering, recompute per-group dup sizes + totals
        self._recompute_group_dupsizes()
        self._update_totals_from_tree()
        self.status.configure(text="Filtered results to current sources.")

    # ---- Export ----
    def on_export(self) -> None:
        if not self.tree.get_children():
            messagebox.showinfo("Export", "Nothing to export.")
            return
        path = filedialog.asksaveasfilename(title="Export CSV", defaultextension=".csv", filetypes=[("CSV files", ".csv"), ("All files", ".*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Group", "Original", "Duplicate", "Size", "Group Dup Size", "Hash"])
                for parent in self.tree.get_children(""):
                    grp = self.tree.set(parent, "grp"); orig = self.tree.item(parent, "text")
                    size = self.tree.set(parent, "size"); dupsz = self.tree.set(parent, "dupsize"); digest = self.tree.set(parent, "hash")
                    children = self.tree.get_children(parent)
                    if not children:
                        w.writerow([grp, orig, "", size, dupsz, digest])
                    else:
                        for child in children:
                            dup = self.tree.item(child, "text")
                            w.writerow([grp, orig, dup, size, dupsz, digest])
            messagebox.showinfo("Export", f"Exported to {path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to export: {e}")

# ----------------------------- Main -----------------------------

def main() -> None:
    app = DuplicateFinderApp(); app.mainloop()

if __name__ == "__main__":
    main()
