"""Régénère Resources/oui.txt.gz depuis le registre public IEEE (MA-L) : python3 tools/update_oui.py"""
import csv
import gzip
import io
import os
import sys
import urllib.request

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = os.path.join(os.path.dirname(__file__), "..", "Resources", "oui.txt.gz")


def main(src=None):
    if src:
        raw = open(src, "rb").read()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0 (Macintosh) Safari/605.1.15",
                                                   "Accept": "text/csv,*/*"})
        raw = urllib.request.urlopen(req, timeout=120).read()
    rows = csv.reader(io.StringIO(raw.decode("utf-8", "ignore")))
    entries = {}
    for r in rows:
        if len(r) >= 3 and r[0] == "MA-L" and len(r[1]) == 6:
            entries[r[1].lower()] = " ".join(r[2].split())
    if len(entries) < 10000:
        sys.exit(f"registre IEEE incomplet ({len(entries)} entrées) : fichier non remplacé")
    body = "".join(f"{k}\t{v}\n" for k, v in sorted(entries.items())).encode()
    with gzip.open(OUT, "wb", compresslevel=9) as f:
        f.write(body)
    print(f"{len(entries)} fabricants → {OUT} ({os.path.getsize(OUT) // 1024} Ko)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
