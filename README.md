# Duplicate Finder (Tkinter, Python 3.10+)

A Tkinter-based GUI **Python script** for locating and managing duplicate files. The program scans one or more directories, identifies sets of files that are identical by cryptographic hash, and provides tools to review, move to a quarantine folder, or delete duplicates.

---

## Overview

* **Technology**: Python standard library only; GUI built with Tkinter.
* **Platforms**: Windows, macOS, Linux.
* **Method**: Full‑file BLAKE2b‑256 hashing on same‑size candidates.

---

## Features

* Select multiple source folders (including drive roots).
* Optional recursion into subfolders; optional following of symlinks.
* Include / exclude filename patterns (e.g., `*.jpg;*.png`) and minimum size filter.
* Determinate progress with file and byte counters.
* Results shown as a tree: one **original** file (oldest modification time) with **duplicate** children.
* Flag column (checkboxes) in addition to standard row selection.
* "Select Duplicates in Group" selects only duplicate rows in the focused group.
* Quarantine move (cross‑device safe: copy‑then‑delete fallback) or permanent delete.
* Export results as CSV.
* Results automatically stay consistent with the current source list.

---

## Requirements

* Python **3.10** or newer installed on the system (run via the `python` interpreter; this is not a packaged/executable app).
* No third‑party dependencies.
* No third‑party dependencies.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/degenerator303/DuplicateFinder.git
cd DuplicateFinder
```

---

## Running

```bash
python DuplicateFinderGUI.py
```

---

## Usage

1. **Add Sources**: Use **Add Folder…** to add directories to scan. Multiple entries are allowed.
2. **Options**:

   * **Include subfolders**: When enabled, scan recursively.
   * **Follow symlinks**: When enabled, follow symbolic links.
   * **Min size (bytes)**: Skip files smaller than this value.
   * **Include patterns / Exclude patterns**: Semicolon‑separated glob patterns. If Include is set, only matching files are considered. Exclude removes matching files.
   * **Quarantine folder**: Destination for the “Move to quarantine” action.
3. **Start**: Click **Start** to begin scanning. The application first counts files, then hashes candidates.
4. **Review Results**:

   * The left column shows file paths. Parents are originals; children are duplicates.
   * Use the **Flag** column (checkboxes) to mark rows. Press **Space** to toggle flags on the current selection.
   * **Select Duplicates in Group** selects only the duplicates in the focused group (never the original).
5. **Actions**:

   * **Open**: Open the selected/flagged files in the default application.
   * **Reveal in Folder**: Open the containing folder (or reveal the file, where supported).
   * **Copy Paths**: Copy absolute paths to the clipboard.
   * **Move to Quarantine**: Move selected/flagged files into the configured quarantine folder. Name collisions receive numeric suffixes. Cross‑device moves are handled via copy‑then‑delete.
   * **Delete Selected**: Permanently delete selected/flagged files. No recycle bin is used.
   * **Export CSV**: Write a CSV file with (Original, Duplicate, Size, Hash) rows.

---

## How It Works

1. **Enumeration**: Walk selected roots; filter by size and patterns; avoid reprocessing the same inode (hard links).
2. **Size bucketing**: Only files with the same size proceed to hashing.
3. **Hashing**: Compute BLAKE2b‑256 over the entire file using 8 MB chunks.
4. **Grouping**: Files with identical `(size, digest)` are duplicates. The original is chosen as the file with the oldest modification time.

The scanner runs in a background thread. UI updates are posted via a queue; cancellation is handled by a thread event.

---

## Output

* **Tree view** of duplicate groups in the GUI.
* **CSV export** with columns: `Original`, `Duplicate`, `Size`, `Hash`.

---

## Notes and Limitations

* Deleting files uses `os.remove()` and does not use the system recycle bin.
* Hashing reads entire files; initial runs on large datasets can take time.
* Network locations and removable drives may be slower and subject to permission errors.
* Following symlinks can lead to repeated content being scanned from multiple entry points; disable if not desired.

---

## License

This project is released under the MIT License. See `LICENSE` for details.
