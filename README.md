# 🔍 FILE TYPE VERIFICATION TOOL

A powerful Python-based CLI tool that analyzes files using **magic number signatures**, **binary analysis**, and **Shannon entropy detection** to accurately identify file types — even when extensions are missing or spoofed.

---

# 🚀 FEATURES

- **50+ file type signatures** with offset support
- **Magic number detection** — reads raw binary headers, not just extensions
- **Extension mismatch detection** — catches disguised or renamed files
- **Shannon entropy analysis** — identifies encrypted, compressed, or obfuscated content
- **Hex dump / binary viewer** — inspect file headers in classic hex format
- **Batch directory scanning** — scan entire folders at once (with optional recursion)
- **JSON / CSV report export** — export results for logging or further processing
- **Colorized CLI output** — clean, readable terminal interface
- **File integrity hashing** — MD5 and SHA-256 checksums for every file
- **Suspicious file detection** — flags executables disguised as common file types

---

# 🧠 HOW IT WORKS

## 🔹 Magic Number Detection

Every file type has a unique byte sequence (magic number) at a specific offset in its binary header. Instead of trusting file extensions, the tool reads raw bytes and compares them against a signature database of 50+ known patterns.

Supported categories:
- Images (JPEG, PNG, GIF, BMP, TIFF, WebP, JPEG 2000, ICO)
- Documents (PDF, MS Office OLE2, OpenXML, RTF)
- Archives (ZIP, RAR, GZIP, BZIP2, XZ, 7-Zip, TAR, Zstandard, LZ4)
- Executables & Binaries (Windows PE, ELF, Mach-O, Shell scripts, Java class)
- Audio (MP3, FLAC, OGG, WAV, APE)
- Video (MP4, MKV/WebM, FLV, ASF/WMV)
- Fonts (WOFF, WOFF2, TrueType, OpenType)
- Databases (SQLite)
- Certificates & Crypto (PEM, DER)
- Text & Source (XML, HTML, UTF-8/UTF-16 BOM)

---

## 🔹 Extension Mismatch Detection

After identifying the true file type via magic bytes, the tool compares the result against the declared file extension. A mismatch flags the file as suspicious — useful for catching malware or improperly renamed files.

---

## 🔹 Shannon Entropy Analysis

Shannon entropy measures the randomness of byte distribution in a file. The tool calculates entropy on a 0–8 scale and classifies the result:

| Entropy Range | Label |
|---|---|
| < 1.0 | Null / Monotone (nearly empty) |
| 1.0 – 3.5 | Plain text / structured |
| 3.5 – 5.5 | Binary data / mixed |
| 5.5 – 7.2 | Compressed data |
| ≥ 7.2 | Encrypted / random / packed |

High entropy (≥ 7.2) triggers a warning about potential encryption or obfuscation.

---

## 🔹 Suspicious File Detection

The tool automatically flags files as **[SUSPICIOUS]** when:
- The declared extension doesn't match the detected type
- An executable binary is disguised as an image, PDF, or document
- A matching magic signature cannot be found at all

---

# 📦 REQUIREMENTS

No external libraries required — uses only Python built-ins.

| Module | Purpose |
|---|---|
| `os`, `sys`, `pathlib` | File system operations |
| `math` | Shannon entropy calculation |
| `json`, `csv` | Report export |
| `struct` | Binary data parsing |
| `argparse` | CLI argument handling |
| `hashlib` | MD5 and SHA-256 hashing |
| `dataclasses` | Structured result objects |

---

# ⚙️ INSTALLATION & USAGE

Clone the repository:

```bash
git clone https://github.com/your-username/FileTypeVerifier.git
cd FileTypeVerifier
```

Run the tool:

```bash
# Analyze a single file
python file_type_verifier.py file.pdf

# Show hex dump of file header
python file_type_verifier.py --hex file.bin

# Scan all files in a directory
python file_type_verifier.py --dir /path/to/folder

# Scan recursively
python file_type_verifier.py --dir /path/to/folder --recursive

# Export results to JSON
python file_type_verifier.py --export report.json file1.pdf file2.docx

# Export results to CSV
python file_type_verifier.py --export report.csv *.bin

# Show only suspicious files
python file_type_verifier.py --suspicious-only --dir ./uploads

# Filter results by category
python file_type_verifier.py --category Executable --dir ./downloads

# List all known magic number signatures
python file_type_verifier.py --list-signatures
```

---

# 📊 SAMPLE OUTPUT

```
╔══════════════════════════════════════════════════════════════╗
║          FILE TYPE VERIFICATION TOOL  v2.0                  ║
║     Magic Numbers · Binary Analysis · Entropy Detection     ║
╚══════════════════════════════════════════════════════════════╝

──────────────────────────────────────────────────────────────
  File      : /home/user/suspicious.jpg
  Size      : 45,312 bytes (44.25 KB)
  Extension : .jpg
  Magic Hex : 4D5A  (offset 0)
  Detected  : Windows Executable [Executable] [SUSPICIOUS]
  Valid Exts: .exe, .dll, .sys
  Ext Check : ✘ MISMATCH
  Entropy   : 6.2341 / 8.0  → Compressed data
  MD5       : d41d8cd98f00b204e9800998ecf8427e
  SHA-256   : e3b0c44298fc1c149afbf4c8996fb92427...

  Notes:
    ⚠️  Extension '.jpg' does not match detected type 'Windows Executable'
    🚨 DANGER: Executable binary disguised as a common file type!
──────────────────────────────────────────────────────────────
```

---

# 📁 PROJECT STRUCTURE

```
FileTypeVerifier/
│
├── file_type_verifier.py   # Main tool — all logic in one file
└── README.md               # Project documentation
```

---

# 🚀 FUTURE IMPROVEMENTS

- YARA rule integration for advanced malware pattern matching
- GUI interface using Tkinter or PyQt
- VirusTotal API lookup for flagged files
- MIME type comparison alongside extension checks
- Support for nested archive scanning (ZIP-in-ZIP)
- Docker container for isolated scanning
- Progress bar for large batch scans
- Magic database hot-reload from external config file

---

# 👨‍💻 AUTHOR

**MD Sami Akhlaq**

- 🔗 LinkedIn: https://www.linkedin.com/in/md-sami-akhlaq-2838b0334/
- 🔗 Facebook: https://www.facebook.com/say.yashh

> This project was built for learning purposes to understand Python CLI development, binary file analysis, and foundational cybersecurity concepts.

---

# 📜 LICENSE

MIT License — open-source and free to use.
