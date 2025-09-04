#!/usr/bin/env python3
"""
Duplicate Finder GUI (Tkinter, stdlib-only)
Python 3.10+

Features
- Select multiple source folders (or drive roots) to scan
- Two-stage dedup: size bucketing then full-file BLAKE2b-256 hashing
- Determinate progress with pre-scan (file & byte counts)
- Start/Stop safe cancellation
- Results in hierarchical Treeview: parent=original (oldest mtime), children=duplicates
- Actions: open file, reveal in folder, copy paths, select duplicates in group,
          export CSV report, delete selected (permanent) or move to quarantine
- Cross-platform (Windows/macOS/Linux), stdlib-only

Notes
- Hash: BLAKE2b with 32-byte digest (≈ SHA-256 resistance) for speed + negligible collision risk
- No recycle bin in stdlib; deleting uses os.remove(). Use quarantine for safer workflow.
- Designed to be responsive and robust against permission errors.
"""
from __future__ import annotations

import os
import sys
import csv
import time
import math
import queue
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Iterable, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ----------------------------- Utilities -----------------------------

CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB chunks for hashing


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
    """Return hex digest of BLAKE2b-256 for full file. None if cancelled.
    """
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
        return "__ERROR__"  # marker digest for unreadable files


def reveal_in_file_manager(path: Path) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(path if path.is_dir() else path.parent)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            # Open and highlight the file if possible
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
    min_size: int = 1  # bytes
    include_patterns: Optional[str] = None  # e.g. "*.jpg;*.png"
    exclude_patterns: Optional[str] = None  # e.g. "*.tmp;*.bak"
    quarantine_dir: Optional[Path] = None


@dataclass
class Progress:
    stage: str  # 'counting' | 'hashing' | 'building' | 'done'
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


# ----------------------------- Worker logic -----------------------------

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

        seen: set[Tuple[int, int]] = set()  # (st_dev, st_ino) to avoid duplicates via hardlinks

        def want(path: Path) -> bool:
            try:
                st = path.stat()
            except (PermissionError, FileNotFoundError, OSError):
                self.errors += 1
                return False
            if not path.is_file():
                return False
            if st.st_size < opts.min_size:
                return False
            # include/exclude filtering
            if include_globs and not any(path.match(g) for g in include_globs):
                return False
            if exclude_globs and any(path.match(g) for g in exclude_globs):
                return False
            # avoid processing the same inode multiple times
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
                if not root.exists():
                    continue
                if root.is_file():
                    if want(root):
                        yield root
                    continue

                if opts.include_subdirs:
                    # walk
                    for dirpath, dirnames, filenames in os.walk(root, followlinks=opts.follow_symlinks):
                        if self.stop.is_set():
                            return
                        dirpath_p = Path(dirpath)
                        for name in filenames:
                            p = dirpath_p / name
                            if want(p):
                                yield p
                else:
                    # only top-level files
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

        # Stage B: size bucketing
        size_map: Dict[int, List[Path]] = {}
        for p in files:
            try:
                sz = int(p.stat().st_size)
            except Exception:
                self.errors += 1
                continue
            size_map.setdefault(sz, []).append(p)

        candidates = [(sz, lst) for sz, lst in size_map.items() if len(lst) > 1]
        candidates.sort(key=lambda t: t[0], reverse=True)  # large files first

        # Prepare progress totals for hashing
        hash_file_total = sum(len(lst) for _, lst in candidates)
        hash_bytes_total = sum(sz * len(lst) for sz, lst in candidates)
        files_hashed = 0
        bytes_done = 0

        digest_map: Dict[Tuple[int, str], List[Path]] = {}

        # Stage C: hashing
        for sz, lst in candidates:
            if self.stop.is_set():
                return
            for p in lst:
                if self.stop.is_set():
                    return
                digest = blake2b_256_of(p, self.stop)
                if digest is None:
                    # cancelled
                    return
                if digest == "__ERROR__":
                    self.errors += 1
                    continue
                digest_map.setdefault((sz, digest), []).append(p)
                files_hashed += 1
                bytes_done += sz
                if files_hashed % 16 == 0 or files_hashed == hash_file_total:
                    self.q_out.put(Progress(
                        "hashing",
                        files_hashed,
                        hash_file_total,
                        bytes_done,
                        hash_bytes_total,
                        files_hashed,
                        0,
                        self.errors,
                    ))

        # Stage D: build groups
        groups: List[Group] = []
        for (sz, dg), paths in digest_map.items():
            if len(paths) > 1:
                groups.append(Group(digest=dg, size=sz, files=sorted(paths)))

        # Pick canonical originals (oldest mtime)
        result: List[Tuple[Path, List[Path], int, str]] = []  # (original, duplicates, size, digest)
        for g in groups:
            try:
                # oldest mtime as canonical original
                orig = min(g.files, key=lambda p: p.stat().st_mtime)
            except Exception:
                orig = g.files[0]
            dups = [p for p in g.files if p != orig]
            result.append((orig, dups, g.size, g.digest))

        # send final payload
        self.q_out.put(("RESULTS", result))
        self.q_out.put(Progress("done", 1, 1, bytes_done, hash_bytes_total, files_hashed, 0, self.errors))


# ----------------------------- GUI Application -----------------------------

class DuplicateFinderApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Duplicate Finder (stdlib)")
        self.geometry("1100x700")
        self.minsize(900, 600)

        self.queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None

        self._build_ui()
        self._configure_style()
        self.after(100, self._poll_queue)

    # ---- UI Construction ----
    def _build_ui(self) -> None:
        root = self
        # Top: source selection frame
        src_frame = ttk.LabelFrame(root, text="Sources")
        src_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        self.src_list = tk.Listbox(src_frame, height=4, selectmode=tk.EXTENDED)
        self.src_list.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 5), pady=10)

        btns = ttk.Frame(src_frame)
        btns.pack(side=tk.LEFT, fill=tk.Y, padx=(5, 10), pady=10)
        ttk.Button(btns, text="Add Folder…", command=self.on_add_folder).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="Remove Selected", command=self.on_remove_selected).pack(fill=tk.X, pady=2)
        ttk.Button(btns, text="Clear", command=self.on_clear_sources).pack(fill=tk.X, pady=2)

        opts = ttk.Frame(src_frame)
        opts.pack(side=tk.RIGHT, fill=tk.X, padx=10, pady=10)
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
            ("Quarantine folder (optional)", ttk.Entry(opts, textvariable=self.var_quarantine, width=40)),
        ]):
            ttk.Label(opts, text=lbl).grid(row=row, column=0, sticky="w", padx=5, pady=2)
            widget.grid(row=row, column=1, sticky="w", padx=5, pady=2)
        ttk.Button(opts, text="Choose…", command=self.on_choose_quarantine).grid(row=5, column=2, padx=5)

        # Middle: controls + progress
        ctrl = ttk.Frame(root)
        ctrl.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0, 10))
        self.btn_start = ttk.Button(ctrl, text="Start", command=self.on_start)
        self.btn_stop = ttk.Button(ctrl, text="Stop", command=self.on_stop, state=tk.DISABLED)
        self.btn_export = ttk.Button(ctrl, text="Export CSV", command=self.on_export, state=tk.DISABLED)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        self.btn_export.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(ctrl, length=300, mode="determinate")
        self.progress.pack(side=tk.LEFT, padx=15)
        self.status = ttk.Label(ctrl, text="Idle")
        self.status.pack(side=tk.LEFT, padx=10)

        # Bottom: results + actions
        bottom = ttk.Panedwindow(root, orient=tk.VERTICAL)
        bottom.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Treeview for groups (hierarchical)
        tree_frame = ttk.Frame(bottom)
        self.tree = ttk.Treeview(tree_frame, columns=("flag", "size", "hash"), show="tree headings")
        self.tree.heading("#0", text="Path")
        self.tree.heading("flag", text="Flag")
        self.tree.heading("size", text="Size")
        self.tree.heading("hash", text="Hash (BLAKE2b-256)")
        self.tree.column("#0", width=700, anchor="w")
        self.tree.column("flag", width=60, anchor="center")
        self.tree.column("size", width=120, anchor="e")
        self.tree.column("hash", width=280, anchor="w")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        # Toggle flag on click in the Flag column
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<space>", self._on_toggle_flag_selection)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        action_frame = ttk.Frame(bottom)
        for txt, cmd in [
            ("Open", self.on_open_file),
            ("Reveal in Folder", self.on_reveal),
            ("Copy Paths", self.on_copy_paths),
            ("Select Duplicates in Group", self.on_select_group_dups),
            ("Toggle Flag on Selection", self.on_toggle_flag_on_selection),
            ("Delete Selected/Flagged…", self.on_delete_selected),
            ("Move Selected/Flagged to Quarantine", self.on_move_selected),
        ]:
            ttk.Button(action_frame, text=txt, command=cmd).pack(side=tk.LEFT, padx=5, pady=5)

        bottom.add(tree_frame, weight=4)
        bottom.add(action_frame, weight=0)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        # Use platform default; tags for coloring rows
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
        # After removing sources, filter existing results to current sources
        self._filter_results_to_sources()

    def on_choose_quarantine(self) -> None:
        path = filedialog.askdirectory(title="Choose quarantine folder")
        if path:
            self.var_quarantine.set(path)

    # ---- Source helpers & filtering ----
    def on_clear_sources(self) -> None:
        self.src_list.delete(0, tk.END)
        self._clear_results()
        self.status.configure(text="Sources cleared. Previous results removed.")
        self.btn_export.configure(state=tk.DISABLED)

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
            self._clear_results()
            self.status.configure(text="All sources removed — cleared results.")
            self.btn_export.configure(state=tk.DISABLED)
            return
        to_delete: List[str] = []
        for parent in self.tree.get_children(""):
            p_path = Path(self.tree.item(parent, "text"))
            if not self._is_under_any_root(p_path, roots):
                to_delete.append(parent)
                continue
            for child in self.tree.get_children(parent):
                c_path = Path(self.tree.item(child, "text"))
                if not self._is_under_any_root(c_path, roots):
                    to_delete.append(child)
            remaining = [c for c in self.tree.get_children(parent) if c not in to_delete]
            if not remaining:
                to_delete.append(parent)
        # Delete deepest-first to avoid parent-before-child errors
        unique_items = list(set(to_delete))
        def _depth2(it: str) -> int:
            d = 0
            cur = it
            while True:
                par = self.tree.parent(cur)
                if not par:
                    break
                d += 1
                cur = par
            return d
        for item in sorted(unique_items, key=_depth2, reverse=True):
            try:
                if getattr(self.tree, "exists", None) and not self.tree.exists(item):
                    continue
                self.tree.delete(item)
            except Exception:
                pass
        self.status.configure(text="Filtered results to current sources.")

    # ---- Scanning controls ----
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

        options = ScanOptions(
            roots=roots,
            include_subdirs=self.var_subdirs.get(),
            follow_symlinks=self.var_symlinks.get(),
            min_size=min_size,
            include_patterns=self.var_incl.get().strip() or None,
            exclude_patterns=self.var_excl.get().strip() or None,
            quarantine_dir=quarantine,
        )

        self._clear_results()
        self.progress.configure(value=0, maximum=100)
        self.status.configure(text="Counting files…")
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
                else:
                    pass
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_queue)

    def _handle_progress(self, p: Progress) -> None:
        if p.stage == "counting":
            # Counting uses bytes_total only for display; bar is indeterminate until we know totals
            self.progress.configure(mode="indeterminate")
            self.progress.start(10)
            self.status.configure(text=f"Counting… Files: {p.current}  Errors: {p.errors}")
        elif p.stage == "hashing":
            self.progress.stop()
            self.progress.configure(mode="determinate")
            total = p.total if p.total else 1
            value = max(0, min(100, int((p.current / total) * 100)))
            self.progress.configure(value=value, maximum=100)
            self.status.configure(
                text=(
                    f"Hashing {p.current}/{p.total} files…  "
                    f"Bytes: {human_bytes(p.bytes_done)}/{human_bytes(p.bytes_total)}  "
                    f"Errors: {p.errors}"
                )
            )
        elif p.stage == "done":
            self.progress.stop()
            self.progress.configure(mode="determinate", value=100)
            self.status.configure(text=f"Done. Hashed {p.files_hashed} files. Errors: {p.errors}")
            self.btn_start.configure(state=tk.NORMAL)
            self.btn_stop.configure(state=tk.DISABLED)
            self.btn_export.configure(state=tk.NORMAL if len(self.tree.get_children()) else tk.DISABLED)
        else:
            # building or other stages
            self.status.configure(text=f"{p.stage.capitalize()}…")

    # ---- Results handling ----
    def _clear_results(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)

    def _handle_results(self, results: List[Tuple[Path, List[Path], int, str]]) -> None:
        # Populate tree: parent = original; children = duplicates
        for orig, dups, size, digest in sorted(results, key=lambda t: (t[2], str(t[0]).lower()), reverse=True):
            parent = self.tree.insert("", tk.END, text=str(orig), values=("☐", human_bytes(size), digest), tags=("original",))
            for dup in dups:
                self.tree.insert(parent, tk.END, text=str(dup), values=("☐", human_bytes(size), digest), tags=("duplicate",))
        self.tree.expand_all = getattr(self.tree, 'expand_all', None)
        # Auto-expand all parents for visibility
        for item in self.tree.get_children():
            self.tree.item(item, open=True)
        self.status.configure(text=f"Found {len(results)} duplicate sets.")
        self.btn_export.configure(state=tk.NORMAL if results else tk.DISABLED)

    # ---- Actions ----
    def _flagged_items(self) -> List[str]:
        items = []
        for parent in self.tree.get_children(""):
            if self.tree.set(parent, "flag") == "☑":
                items.append(parent)
            for child in self.tree.get_children(parent):
                if self.tree.set(child, "flag") == "☑":
                    items.append(child)
        return items

    def _items_to_paths(self, items: List[str]) -> List[Path]:
        return [Path(self.tree.item(it, "text")) for it in items]

    def _active_items(self) -> List[str]:
        flagged = self._flagged_items()
        if flagged:
            return flagged
        return list(self.tree.selection())

    def _active_paths(self) -> List[Path]:
        return self._items_to_paths(self._active_items())

    def on_open_file(self) -> None:
        for p in self._active_paths():
            try:
                if sys.platform.startswith("win"):
                    os.startfile(p)  # type: ignore[attr-defined]
                elif sys.platform == "darwin":
                    import subprocess
                    subprocess.Popen(["open", str(p)])
                else:
                    import subprocess
                    subprocess.Popen(["xdg-open", str(p)])
            except Exception as e:
                messagebox.showerror("Open Error", f"Could not open {p}: {e}")

    def on_reveal(self) -> None:
        for p in self._active_paths():
            reveal_in_file_manager(p)

    def on_toggle_flag_on_selection(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        for item in sel:
            current = self.tree.set(item, "flag")
            self.tree.set(item, "flag", "☐" if current == "☑" else "☑")
        self.status.configure(text=f"Toggled flag on {len(sel)} item(s)")

    def _on_tree_click(self, event) -> None:
        # Toggle checkbox when clicking in Flag column
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        if col != "#1":  # #0 is tree, #1 is 'flag'
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        current = self.tree.set(item, "flag")
        self.tree.set(item, "flag", "☐" if current == "☑" else "☑")

    def _on_toggle_flag_selection(self, event=None) -> None:
        self.on_toggle_flag_on_selection()

    def on_copy_paths(self) -> None:
        paths = [str(p) for p in self._active_paths()]
        if not paths:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(paths))
        self.status.configure(text=f"Copied {len(paths)} path(s) to clipboard.")

    def on_select_group_dups(self) -> None:
        # Select only duplicates in the focused group (never the original)
        item = self.tree.focus()
        if not item:
            sel = self.tree.selection()
            if not sel:
                return
            item = sel[0]
        parent = self.tree.parent(item)
        if parent:  # item is a child -> use its parent
            group_root = parent
        else:       # item is a root/original
            group_root = item
        children = self.tree.get_children(group_root)
        if not children:
            return
        self.tree.selection_set(children)

    def on_delete_selected(self) -> None:
        items = self._active_items()
        paths = [p for p in self._items_to_paths(items) if p.exists()]
        if not paths:
            messagebox.showinfo("Delete", "No existing files selected.")
            return
        if not messagebox.askyesno("Delete Selected",
                                   f"Permanently delete {len(paths)} file(s)? This cannot be undone."):
            return
        deleted = 0
        errors = 0
        for p in paths:
            try:
                p.unlink(missing_ok=True)
                deleted += 1
            except Exception:
                errors += 1
        self.status.configure(text=f"Deleted {deleted} file(s). Errors: {errors}")
        # Remove missing items from tree
        self._prune_missing_tree_items()

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
        paths = [p for p in self._items_to_paths(items) if p.exists()]
        if not paths:
            messagebox.showinfo("Move", "No existing files selected.")
            return
        import shutil, errno
        moved = 0
        errors = 0
        for p in paths:
            try:
                target = qdir / p.name
                base = target
                i = 1
                while target.exists():
                    target = base.with_name(f"{base.stem} ({i}){base.suffix}")
                    i += 1
                try:
                    p.replace(target)
                except OSError as e:
                    if getattr(e, 'errno', None) == errno.EXDEV:
                        shutil.copy2(p, target)
                        p.unlink()
                    else:
                        raise
                moved += 1
            except Exception:
                errors += 1
        self.status.configure(text=f"Moved {moved} file(s) to quarantine. Errors: {errors}")
        self._prune_missing_tree_items()

    def _prune_missing_tree_items(self) -> None:
        # Remove rows for files that no longer exist; if a parent has no children, remove it too
        to_delete: List[str] = []
        for parent in self.tree.get_children(""):
            parent_path = Path(self.tree.item(parent, "text"))
            if not parent_path.exists():
                to_delete.append(parent)
                continue
            for child in self.tree.get_children(parent):
                if not Path(self.tree.item(child, "text")).exists():
                    to_delete.append(child)
            remaining_children = [c for c in self.tree.get_children(parent) if c not in to_delete]
            if not remaining_children:
                to_delete.append(parent)
        # Delete deepest-first to avoid TclError when deleting a parent before its children
        unique_items = list(set(to_delete))
        def _depth(it: str) -> int:
            d = 0
            cur = it
            while True:
                par = self.tree.parent(cur)
                if not par:
                    break
                d += 1
                cur = par
            return d
        for item in sorted(unique_items, key=_depth, reverse=True):
            try:
                # Some Tk versions expose Treeview.exists; guard if absent
                if getattr(self.tree, "exists", None) and not self.tree.exists(item):
                    continue
                self.tree.delete(item)
            except Exception:
                # If already gone, ignore
                pass

    def on_export(self) -> None:
        if not self.tree.get_children():
            messagebox.showinfo("Export", "Nothing to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", ".csv"), ("All files", ".*")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Original", "Duplicate", "Size", "Hash"])
                for parent in self.tree.get_children(""):
                    orig = self.tree.item(parent, "text")
                    size = self.tree.set(parent, "size")
                    digest = self.tree.set(parent, "hash")
                    children = self.tree.get_children(parent)
                    if not children:
                        # no duplicates? still record
                        w.writerow([orig, "", size, digest])
                    else:
                        for child in children:
                            dup = self.tree.item(child, "text")
                            w.writerow([orig, dup, size, digest])
            messagebox.showinfo("Export", f"Exported to {path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to export: {e}")


# ----------------------------- Main -----------------------------

def main() -> None:
    app = DuplicateFinderApp()
    app.mainloop()


if __name__ == "__main__":
    main()
