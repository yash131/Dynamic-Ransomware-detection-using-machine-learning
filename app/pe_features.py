"""
Static PE feature extraction.

SAFETY: uploaded bytes are only ever *parsed* with pefile (header fields). They are never
written to disk, imported, loaded, or executed.

Feature names/semantics follow the columns of the training CSV used in
scripts/original_training_script.py (PE-header based malware dataset):
  Machine, DebugSize, DebugRVA, MajorImageVersion, MajorOSVersion, ExportRVA, ExportSize,
  IatVRA, MajorLinkerVersion, MinorLinkerVersion, NumberOfSections, SizeOfStackReserve,
  DllCharacteristics, ResourceSize, BitcoinAddresses
followed by the 5 engineered columns appended by feature_engineering().
"""
import re
import pefile

RAW_FEATURES = [
    "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
    "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
    "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
    "BitcoinAddresses",
]
ENGINEERED_FEATURES = ["has_crypto", "size_ratio", "section_ratio", "high_iat", "entropy_like"]
ALL_FEATURES = RAW_FEATURES + ENGINEERED_FEATURES

_BTC_RE = re.compile(rb"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")

DIR_EXPORT, DIR_RESOURCE, DIR_DEBUG, DIR_IAT = 0, 2, 6, 12


class NotAPEFile(ValueError):
    """Raised when the upload is not a parseable Windows PE file."""


def extract_features(data: bytes) -> dict:
    if len(data) < 64 or data[:2] != b"MZ":
        raise NotAPEFile("File does not start with a DOS 'MZ' header.")
    try:
        pe = pefile.PE(data=data, fast_load=True)   # header-only parse
    except pefile.PEFormatError as exc:
        raise NotAPEFile(f"Not a valid PE file: {exc}") from None
    try:
        oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
        dd = oh.DATA_DIRECTORY

        def rva(i):
            return int(dd[i].VirtualAddress) if i < len(dd) else 0

        def size(i):
            return int(dd[i].Size) if i < len(dd) else 0

        f = {
            "Machine": int(fh.Machine),
            "DebugSize": size(DIR_DEBUG),
            "DebugRVA": rva(DIR_DEBUG),
            "MajorImageVersion": int(oh.MajorImageVersion),
            "MajorOSVersion": int(oh.MajorOperatingSystemVersion),
            "ExportRVA": rva(DIR_EXPORT),
            "ExportSize": size(DIR_EXPORT),
            "IatVRA": rva(DIR_IAT),
            "MajorLinkerVersion": int(oh.MajorLinkerVersion),
            "MinorLinkerVersion": int(oh.MinorLinkerVersion),
            "NumberOfSections": int(fh.NumberOfSections),
            "SizeOfStackReserve": int(oh.SizeOfStackReserve),
            "DllCharacteristics": int(oh.DllCharacteristics),
            "ResourceSize": size(DIR_RESOURCE),
            "BitcoinAddresses": len(_BTC_RE.findall(data)),
        }
    finally:
        pe.close()

    # Same formulas as feature_engineering() in the training script.
    f["has_crypto"] = int(f["BitcoinAddresses"] > 0)
    f["size_ratio"] = f["ResourceSize"] / (f["SizeOfStackReserve"] + 1)
    f["section_ratio"] = f["NumberOfSections"] / (f["SizeOfStackReserve"] + 1)
    f["high_iat"] = int(f["IatVRA"] > 100000)
    f["entropy_like"] = f["ResourceSize"] * f["ExportSize"]
    return f
