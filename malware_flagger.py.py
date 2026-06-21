"""
Downloads Folder Safety Scanner
--------------------------------
A simple Windows tool that:
  1. Walks through your Downloads folder
  2. Flags files with risky extensions (.exe, .scr, .bat, .vbs, .js, .ps1, etc.)
  3. Flags "double extension" tricks (e.g. invoice.pdf.exe)
  4. Shows file size, last modified date, and a SHA-256 hash for each flagged
     file, so you can look it up on VirusTotal (https://www.virustotal.com)
     if you're unsure.
  5. Optionally triggers a REAL antivirus scan of the folder using the
     built-in Windows Defender engine (this is the part that can actually
     detect malware -- extension checks alone cannot).

This script does NOT detect malware by itself. It is a triage helper to
point you at files worth checking more closely.

Usage:
    python scan_downloads.py
    python scan_downloads.py "C:\\path\\to\\folder"   (optional custom folder)
"""

import os
import sys
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path

# Extensions commonly used to deliver malware. Not exhaustive -- just a
# starting point for what's worth a second look.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".msi", ".msp", ".jar",
    ".hta", ".reg", ".lnk", ".inf", ".gadget",
    ".cpl", ".dll", ".scf", ".chm",
}

# Extensions that are commonly faked/disguised behind a "safe-looking"
# first extension, e.g. "invoice.pdf.exe"
COMMONLY_SPOOFED_FIRST_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt",
    ".jpg", ".jpeg", ".png", ".mp3", ".mp4", ".zip",
}


def get_downloads_folder() -> Path:
    """Return the current user's Downloads folder on Windows."""
    home = Path.home()
    downloads = home / "Downloads"
    return downloads


def sha256_of_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 hash of a file, reading in chunks (safe for large files)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError) as e:
        return f"<could not hash: {e}>"


def has_double_extension(filename: str) -> bool:
    """Detect patterns like invoice.pdf.exe -- a classic disguise trick."""
    parts = filename.lower().split(".")
    if len(parts) < 3:
        return False
    second_to_last_ext = "." + parts[-2]
    last_ext = "." + parts[-1]
    return (
        second_to_last_ext in COMMONLY_SPOOFED_FIRST_EXT
        and last_ext in RISKY_EXTENSIONS
    )


def scan_folder(folder: Path):
    flagged = []

    if not folder.exists():
        print(f"Folder not found: {folder}")
        return flagged

    for root, _dirs, files in os.walk(folder):
        for name in files:
            path = Path(root) / name
            ext = path.suffix.lower()

            reason = None
            if ext in RISKY_EXTENSIONS:
                reason = f"risky extension ({ext})"
            if has_double_extension(name):
                reason = "double extension disguise (e.g. file.pdf.exe)"

            if reason:
                try:
                    stat = path.stat()
                    size_kb = stat.st_size / 1024
                    modified = datetime.fromtimestamp(stat.st_mtime).strftime(
                        "%Y-%m-%d %H:%M"
                    )
                except OSError:
                    size_kb = 0
                    modified = "unknown"

                flagged.append(
                    {
                        "path": str(path),
                        "reason": reason,
                        "size_kb": round(size_kb, 1),
                        "modified": modified,
                        "sha256": sha256_of_file(path),
                    }
                )

    return flagged


def print_report(flagged):
    if not flagged:
        print("\nNo files with risky extensions or disguised names were found.")
        print("(This does NOT guarantee the folder is malware-free -- it only")
        print(" checks file names/extensions, not file contents.)\n")
        return

    print(f"\n{len(flagged)} file(s) flagged for manual review:\n")
    print("-" * 80)
    for item in flagged:
        print(f"File:     {item['path']}")
        print(f"Reason:   {item['reason']}")
        print(f"Size:     {item['size_kb']} KB")
        print(f"Modified: {item['modified']}")
        print(f"SHA-256:  {item['sha256']}")
        print("  -> You can paste this hash into https://www.virustotal.com")
        print("     to check it against dozens of antivirus engines.")
        print("-" * 80)


def offer_defender_scan(folder: Path):
    """Offer to run a real Windows Defender scan on the folder."""
    answer = input(
        "\nWould you like to run a REAL antivirus scan (Windows Defender) "
        "on this folder now? [y/N]: "
    ).strip().lower()

    if answer != "y":
        print("Skipping Defender scan. (You can run it later from Windows Security.)")
        return

    defender_path = (
        r"C:\Program Files\Windows Defender\MpCmdRun.exe"
    )

    if not os.path.exists(defender_path):
        print(
            "Could not find MpCmdRun.exe at the expected location.\n"
            "You can run a manual scan instead via:\n"
            "  Settings > Privacy & Security > Windows Security > Virus & threat protection\n"
            "  > Scan options > Custom scan > select your Downloads folder."
        )
        return

    print("Running Windows Defender custom scan... this may take a few minutes.")
    try:
        result = subprocess.run(
            [defender_path, "-Scan", "-ScanType", "3", "-File", str(folder)],
            capture_output=True,
            text=True,
            timeout=1800,
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"Defender exited with code {result.returncode}:")
            print(result.stderr)
        else:
            print("Defender scan complete. Check Windows Security app for full results.")
    except subprocess.TimeoutExpired:
        print("Scan timed out after 30 minutes. Try running it from Windows Security instead.")
    except Exception as e:
        print(f"Could not run Defender scan: {e}")


def main():
    if len(sys.argv) > 1:
        folder = Path(sys.argv[1])
    else:
        folder = get_downloads_folder()

    print(f"Scanning: {folder}\n")
    flagged = scan_folder(folder)
    print_report(flagged)

    if os.name == "nt":
        offer_defender_scan(folder)
    else:
        print(
            "\nNote: Windows Defender scanning is only available on Windows. "
            "Skipping that step."
        )


if __name__ == "__main__":
    main()