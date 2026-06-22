#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          FILE TYPE VERIFICATION TOOL v2.0                   ║
║     Magic Number + Binary Analysis + Entropy Detection      ║
╚══════════════════════════════════════════════════════════════╝

Features:
  - 50+ file type signatures with offset support
  - Hex dump / binary viewer
  - Extension mismatch detection
  - Shannon entropy analysis (detects encryption/compression)
  - Batch directory scanning
  - JSON / CSV report export
  - Colorized CLI output

Usage:
  python file_type_verifier.py file.pdf
  python file_type_verifier.py --hex file.bin
  python file_type_verifier.py --dir /path/to/folder
  python file_type_verifier.py --export report.json file1 file2
"""

import os
import sys
import math
import json
import csv
import struct
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional

# ANSI COLOR HELPERS
class Color:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"

def c(text, color): return f"{color}{text}{Color.RESET}"
def bold(text):     return c(text, Color.BOLD)
def ok(text):       return c(text, Color.GREEN)
def warn(text):     return c(text, Color.YELLOW)
def err(text):      return c(text, Color.RED)
def info(text):     return c(text, Color.CYAN)

NO_COLOR = not sys.stdout.isatty()
if NO_COLOR:
    for attr in vars(Color):
        if not attr.startswith("_"):
            setattr(Color, attr, "")

# MAGIC NUMBER DATABASE
# Each entry: (magic_bytes, offset, label, category, extensions)
# magic_bytes: bytes or list of bytes (multiple signatures for same type)

SIGNATURES = [
    (b"\xFF\xD8\xFF",                 0, "JPEG Image",          "Image",    [".jpg", ".jpeg"]),
    (b"\x89PNG\r\n\x1a\n",           0, "PNG Image",           "Image",    [".png"]),
    (b"GIF87a",                       0, "GIF Image (87a)",     "Image",    [".gif"]),
    (b"GIF89a",                       0, "GIF Image (89a)",     "Image",    [".gif"]),
    (b"BM",                           0, "BMP Image",           "Image",    [".bmp"]),
    (b"\x00\x00\x01\x00",            0, "ICO Icon",             "Image",    [".ico"]),
    (b"II\x2A\x00",                  0, "TIFF Image (LE)",      "Image",    [".tif", ".tiff"]),
    (b"MM\x00\x2A",                  0, "TIFF Image (BE)",      "Image",    [".tif", ".tiff"]),
    (b"RIFF",                         0, "WebP Image",          "Image",    [".webp"]),   # + WEBP at offset 8
    (b"\x00\x00\x00\x0C\x6A\x50\x20\x20", 0, "JPEG 2000",     "Image",    [".jp2", ".j2k"]),
    (b"%PDF-",                        0, "PDF Document",        "Document", [".pdf"]),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 0, "MS Office (OLE2)", "Document", [".doc", ".xls", ".ppt"]),
    (b"PK\x03\x04",                  0, "ZIP / Office OpenXML","Archive",  [".zip", ".docx", ".xlsx", ".pptx", ".odt"]),
    (b"{\x5C\rtf",                   0, "RTF Document",        "Document", [".rtf"]),
    (b"\x09\x04\x06\x00\x00\x00\x10\x00", 0, "Excel 97-2003", "Document", [".xls"]),
    (b"PK\x05\x06",                  0, "ZIP (empty)",         "Archive",  [".zip"]),
    (b"PK\x07\x08",                  0, "ZIP (spanned)",       "Archive",  [".zip"]),
    (b"Rar!\x1a\x07\x00",           0, "RAR Archive v4",      "Archive",  [".rar"]),
    (b"Rar!\x1a\x07\x01\x00",      0, "RAR Archive v5",      "Archive",  [".rar"]),
    (b"\x1f\x8b",                    0, "GZIP Archive",        "Archive",  [".gz", ".tar.gz"]),
    (b"BZh",                         0, "BZIP2 Archive",       "Archive",  [".bz2"]),
    (b"\xFD7zXZ\x00",               0, "XZ Archive",          "Archive",  [".xz"]),
    (b"7z\xBC\xAF'\x1C",            0, "7-Zip Archive",       "Archive",  [".7z"]),
    (b"ustar",                       257,"TAR Archive",        "Archive",  [".tar"]),
    (b"LZIP",                        0, "LZIP Archive",        "Archive",  [".lz"]),
    (b"MZ",                          0, "Windows Executable",  "Executable",[".exe", ".dll", ".sys"]),
    (b"\x7fELF",                     0, "ELF Binary (Linux)",  "Executable",[".elf", ""]),
    (b"\xCE\xFA\xED\xFE",           0, "Mach-O Binary (32-bit)","Executable",[""]),
    (b"\xCF\xFA\xED\xFE",           0, "Mach-O Binary (64-bit)","Executable",[""]),
    (b"\xFE\xED\xFA\xCE",           0, "Mach-O Binary (BE32)", "Executable",[""]),
    (b"#!",                          0, "Shell Script",        "Script",   [".sh", ".bash"]),
    (b"#!/usr/bin/python",           0, "Python Script",       "Script",   [".py"]),
    (b"\xCA\xFE\xBA\xBE",           0, "Java Class File",     "Executable",[".class"]),
    (b"ID3",                         0, "MP3 Audio (ID3 tag)", "Audio",    [".mp3"]),
    (b"\xFF\xFB",                    0, "MP3 Audio",           "Audio",    [".mp3"]),
    (b"fLaC",                        0, "FLAC Audio",          "Audio",    [".flac"]),
    (b"OggS",                        0, "OGG Audio/Video",     "Audio",    [".ogg", ".ogv"]),
    (b"RIFF",                        0, "WAV Audio",           "Audio",    [".wav"]),  # + WAVE at offset 8
    (b"MAC ",                        0, "Monkey's Audio",      "Audio",    [".ape"]),
    (b"\x00\x00\x00\x14ftyp",       0, "MP4 Video",           "Video",    [".mp4", ".m4v"]),
    (b"\x1aE\xdf\xa3",              0, "Matroska/WebM Video", "Video",    [".mkv", ".webm"]),
    (b"FLV\x01",                    0, "Flash Video",         "Video",    [".flv"]),
    (b"\x30\x26\xB2\x75",          0, "ASF/WMV/WMA",         "Video",    [".asf", ".wmv", ".wma"]),
    (b"wOFF",                        0, "WOFF Font",           "Font",     [".woff"]),
    (b"wOF2",                        0, "WOFF2 Font",          "Font",     [".woff2"]),
    (b"\x00\x01\x00\x00\x00",      0, "TrueType Font",       "Font",     [".ttf"]),
    (b"OTTO",                        0, "OpenType Font (CFF)", "Font",     [".otf"]),
    (b"SQLite format 3\x00",        0, "SQLite Database",     "Database", [".sqlite", ".db"]),
    (b"\x53\x51\x4C",               0, "SQLite (alt sig)",    "Database", [".sqlite"]),
    (b"MBR",                         0, "MBR Disk Image",      "DiskImage",[".img"]),
    (b"\x45\x46\x49\x20\x50\x41\x52\x54", 512, "GPT Disk Image","DiskImage",[".img"]),
    (b"-----BEGIN ",                 0, "PEM Certificate/Key", "Crypto",   [".pem", ".crt", ".key"]),
    (b"\x30\x82",                    0, "DER Certificate",     "Crypto",   [".der", ".cer"]),
    (b"<?xml",                       0, "XML Document",        "Text",     [".xml", ".svg", ".xhtml"]),
    (b"<!DOCTYPE",                   0, "HTML Document",       "Text",     [".html", ".htm"]),
    (b"<html",                       0, "HTML Document",       "Text",     [".html", ".htm"]),
    (b"\xEF\xBB\xBF",               0, "UTF-8 BOM Text",      "Text",     [".txt"]),
    (b"\xFF\xFE",                    0, "UTF-16 LE Text",      "Text",     [".txt"]),
    (b"\xFE\xFF",                    0, "UTF-16 BE Text",      "Text",     [".txt"]),
    (b"\x28\xB5\x2F\xFD",           0, "Zstandard Archive",   "Archive",  [".zst"]),
    (b"LZ4 ",                        0, "LZ4 Archive",         "Archive",  [".lz4"]),
]

# Maximum bytes needed for any signature check
MAX_READ = max(
    sig[1] + len(sig[0]) for sig in SIGNATURES
) + 16


# RESULT DATACLASS

@dataclass
class FileResult:
    path: str
    size_bytes: int
    declared_extension: str
    detected_type: str
    detected_category: str
    valid_extensions: list
    extension_match: bool
    entropy: float
    entropy_label: str
    md5: str
    sha256: str
    magic_hex: str
    magic_offset: int
    timestamp: str
    suspicious: bool
    notes: list


class FileVerifier:

    def __init__(self, hex_rows: int = 16):
        self.hex_rows = hex_rows  # bytes per hex dump row

    # Magic Number Detection
    def detect_magic(self, data: bytes) -> Optional[tuple]:
        """
        Scan the signature database against raw bytes.
        Returns the best (longest) match.
        """
        best = None
        for (magic, offset, label, category, exts) in SIGNATURES:
            end = offset + len(magic)
            if len(data) >= end:
                if data[offset:end] == magic:
                    if best is None or len(magic) > len(best[0]):
                        best = (magic, offset, label, category, exts)
        return best

    # Shannon Entropy
    def shannon_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy (bits per byte).
        0 = all same bytes (e.g., null file)
        8 = maximum randomness (encrypted/compressed/random)
        """
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def entropy_label(self, entropy: float) -> str:
        if entropy < 1.0:  return "Null/Monotone (nearly empty)"
        if entropy < 3.5:  return "Plain text / structured"
        if entropy < 5.5:  return "Binary data / mixed"
        if entropy < 7.2:  return "Compressed data"
        return "Encrypted / random / packed"

    # File Hashes
    def compute_hashes(self, path: str) -> tuple:
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha.update(chunk)
        return md5.hexdigest(), sha.hexdigest()

    # Hex Dump
    def hex_dump(self, data: bytes, limit: int = 256) -> str:
        """
        Classic hex dump with offset | hex | ASCII columns.
        """
        lines = []
        data = data[:limit]
        for i in range(0, len(data), 16):
            row = data[i:i+16]
            offset_str = c(f"{i:08X}", Color.GRAY)
            hex_part   = " ".join(f"{b:02X}" for b in row)
            hex_part   = f"{hex_part:<47}"
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"  {offset_str}  {c(hex_part, Color.CYAN)}  {c(ascii_part, Color.WHITE)}")
        return "\n".join(lines)

    # WEBP special check
    def is_webp(self, data: bytes) -> bool:
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"

    def is_wav(self, data: bytes) -> bool:
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE"

    
    def analyze(self, filepath: str) -> FileResult:
        path    = Path(filepath)
        ext     = path.suffix.lower()
        notes   = []
        suspicious = False

        
        try:
            with open(filepath, "rb") as f:
                data = f.read(MAX_READ)
            full_size = os.path.getsize(filepath)
        except PermissionError:
            raise RuntimeError(f"Permission denied: {filepath}")
        except FileNotFoundError:
            raise RuntimeError(f"File not found: {filepath}")

        # Magic detection
        match = self.detect_magic(data)
        if match:
            magic_bytes, magic_offset, label, category, valid_exts = match
            magic_hex = magic_bytes.hex().upper()
            # Refine RIFF subtypes
            if label == "WebP Image" and not self.is_webp(data):
                if self.is_wav(data):
                    label, category, valid_exts, magic_hex = (
                        "WAV Audio", "Audio", [".wav"], magic_hex
                    )
                else:
                    label, category, valid_exts = (
                        "RIFF Container (unknown subtype)", "Binary", []
                    )
        else:
            label, category, valid_exts = "Unknown / Unrecognized", "Unknown", []
            magic_hex = data[:8].hex().upper() if data else "N/A"
            magic_offset = 0
            notes.append("No matching magic signature found.")

        # Extension mismatch check
        ext_match = ext in valid_exts if valid_exts else None
        if valid_exts and not ext_match:
            suspicious = True
            notes.append(
                f"⚠️  Extension '{ext or '(none)'}' does not match detected type '{label}' "
                f"(expected: {', '.join(valid_exts)})"
            )

        # Entropy
        entropy_val   = self.shannon_entropy(data)
        entropy_lbl   = self.entropy_label(entropy_val)
        if entropy_val >= 7.2:
            notes.append("🔐 High entropy — file may be encrypted, compressed, or obfuscated.")

        # Executable in disguise?
        if category == "Executable" and ext in (".jpg", ".png", ".pdf", ".docx", ".txt"):
            suspicious = True
            notes.append("🚨 DANGER: Executable binary disguised as a common file type!")

        # Hashes
        md5_hash, sha256_hash = self.compute_hashes(filepath)

        return FileResult(
            path              = str(path.resolve()),
            size_bytes        = full_size,
            declared_extension= ext or "(none)",
            detected_type     = label,
            detected_category = category,
            valid_extensions  = valid_exts,
            extension_match   = bool(ext_match),
            entropy           = entropy_val,
            entropy_label     = entropy_lbl,
            md5               = md5_hash,
            sha256            = sha256_hash,
            magic_hex         = magic_hex,
            magic_offset      = magic_offset if match else 0,
            timestamp         = datetime.now().isoformat(),
            suspicious        = suspicious,
            notes             = notes,
        )



# DISPLAY / REPORT

def print_banner():
    print(c("""
╔══════════════════════════════════════════════════════════════╗
║          FILE TYPE VERIFICATION TOOL  v2.0                  ║
║     Magic Numbers · Binary Analysis · Entropy Detection     ║
╚══════════════════════════════════════════════════════════════╝""", Color.CYAN))

def print_result(r: FileResult, show_hex: bool = False, raw_data: bytes = b"", verifier=None):
    status = c("✔ MATCH", Color.GREEN) if r.extension_match else (
             c("✘ MISMATCH", Color.RED) if r.valid_extensions else
             c("? UNKNOWN", Color.YELLOW))

    susp_tag = c(" [SUSPICIOUS]", Color.RED) if r.suspicious else ""

    print(f"\n{'─'*62}")
    print(f"  {bold('File')}      : {c(r.path, Color.WHITE)}")
    print(f"  {bold('Size')}      : {r.size_bytes:,} bytes ({r.size_bytes / 1024:.2f} KB)")
    print(f"  {bold('Extension')} : {c(r.declared_extension, Color.YELLOW)}")
    print(f"  {bold('Magic Hex')} : {c(r.magic_hex, Color.MAGENTA)}  (offset {r.magic_offset})")
    print(f"  {bold('Detected')}  : {c(r.detected_type, Color.CYAN)} [{r.detected_category}]{susp_tag}")
    print(f"  {bold('Valid Exts')}: {', '.join(r.valid_extensions) or 'N/A'}")
    print(f"  {bold('Ext Check')} : {status}")
    print(f"  {bold('Entropy')}   : {c(str(r.entropy), Color.BLUE)} / 8.0  → {r.entropy_label}")
    print(f"  {bold('MD5')}       : {c(r.md5, Color.GRAY)}")
    print(f"  {bold('SHA-256')}   : {c(r.sha256, Color.GRAY)}")

    if r.notes:
        print(f"\n  {bold('Notes')}:")
        for note in r.notes:
            print(f"    {warn(note)}")

    if show_hex and raw_data and verifier:
        print(f"\n  {bold('Hex Dump')} (first {min(256, len(raw_data))} bytes):")
        print(f"  {'─'*60}")
        print(f"  {'Offset':10}  {'Hex':47}  ASCII")
        print(f"  {'─'*60}")
        print(verifier.hex_dump(raw_data, limit=256))

    print(f"{'─'*62}")


def export_json(results: list, outpath: str):
    with open(outpath, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(ok(f"\n✔ JSON report saved → {outpath}"))


def export_csv(results: list, outpath: str):
    if not results:
        return
    fields = list(asdict(results[0]).keys())
    with open(outpath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = asdict(r)
            row["valid_extensions"] = ",".join(row["valid_extensions"])
            row["notes"]            = " | ".join(row["notes"])
            w.writerow(row)
    print(ok(f"✔ CSV report saved  → {outpath}"))


# CLI

def build_parser():
    p = argparse.ArgumentParser(
        description="File Type Verification Tool — Magic Numbers + Binary Analysis",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  %(prog)s photo.jpg
  %(prog)s --hex suspicious.exe
  %(prog)s --dir ./uploads
  %(prog)s --export report.json file1.pdf file2.docx
  %(prog)s --export report.csv *.bin
        """
    )
    p.add_argument("files", nargs="*", help="File(s) to analyze")
    p.add_argument("--hex", "-x", action="store_true",
                   help="Show hex dump of file header")
    p.add_argument("--dir", "-d", metavar="DIRECTORY",
                   help="Scan all files in a directory")
    p.add_argument("--recursive", "-r", action="store_true",
                   help="Scan directory recursively")
    p.add_argument("--export", "-e", metavar="OUTPUT",
                   help="Export results to JSON or CSV (auto-detected by extension)")
    p.add_argument("--suspicious-only", "-s", action="store_true",
                   help="Only show suspicious files")
    p.add_argument("--category", "-c", metavar="CAT",
                   help="Filter by category (e.g. Image, Archive, Executable)")
    p.add_argument("--list-signatures", "-l", action="store_true",
                   help="List all known magic number signatures")
    return p


def list_signatures():
    cats = {}
    for (magic, offset, label, category, exts) in SIGNATURES:
        cats.setdefault(category, []).append((magic, offset, label, exts))
    for cat, entries in sorted(cats.items()):
        print(c(f"\n  [{cat}]", Color.CYAN))
        for (magic, offset, label, exts) in entries:
            hex_str = magic.hex().upper()
            ext_str = ", ".join(exts) if exts else "varies"
            print(f"    {c(hex_str, Color.MAGENTA):<32}  offset={offset:<4}  {label:<35}  {c(ext_str, Color.GRAY)}")


def collect_files(args) -> list:
    targets = list(args.files)
    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(err(f"Not a directory: {args.dir}"))
            sys.exit(1)
        pattern = "**/*" if args.recursive else "*"
        targets += [str(p) for p in d.glob(pattern) if p.is_file()]
    return targets


def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if args.list_signatures:
        print(info("\n  Known Magic Number Signatures:"))
        list_signatures()
        return

    targets = collect_files(args)
    if not targets:
        parser.print_help()
        return

    verifier = FileVerifier()
    results  = []
    errors   = []

    for filepath in targets:
        try:
            result = verifier.analyze(filepath)
        except RuntimeError as exc:
            errors.append(str(exc))
            print(err(f"\n  ✘ {exc}"))
            continue

        # Filters
        if args.suspicious_only and not result.suspicious:
            continue
        if args.category and result.detected_category.lower() != args.category.lower():
            continue

        results.append(result)

        # Read raw header for hex dump
        raw_data = b""
        if args.hex:
            with open(filepath, "rb") as f:
                raw_data = f.read(256)

        print_result(result, show_hex=args.hex, raw_data=raw_data, verifier=verifier)

    # ── Summary ──────────────────────────────
    if len(results) > 1:
        suspicious_count = sum(1 for r in results if r.suspicious)
        print(f"\n{'═'*62}")
        print(f"  {bold('SCAN SUMMARY')}")
        print(f"  Files analyzed : {len(results)}")
        print(f"  Suspicious     : {c(str(suspicious_count), Color.RED) if suspicious_count else ok('0')}")
        print(f"  Errors         : {len(errors)}")
        cats = {}
        for r in results:
            cats[r.detected_category] = cats.get(r.detected_category, 0) + 1
        print(f"  Categories     :", ", ".join(f"{k}({v})" for k, v in sorted(cats.items())))
        print(f"{'═'*62}")

    # Export
    if args.export and results:
        out = args.export
        if out.endswith(".csv"):
            export_csv(results, out)
        else:
            if not out.endswith(".json"):
                out += ".json"
            export_json(results, out)


if __name__ == "__main__":
    main()
