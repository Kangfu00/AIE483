"""ตรวจว่า issue บน GitHub ยังตรงกับรูปแบบที่กำหนดไว้

ใช้ได้ทุกครั้งที่แก้ issue เพราะตรวจกับ GitHub ตรง ๆ ไม่ต้องมีไฟล์ draft ในเครื่อง

    PYTHONIOENCODING=utf-8 python -m calibration.verify_issue 1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

REPO = "Kangfu00/AIE483"

REQUIRED_HEADINGS = ["## บริบท", "## เป้าหมาย", "## ภารกิจ", "## วิธีตรวจ"]
FORBIDDEN_CHARS = {"em dash": "\u2014", "en dash": "\u2013", "curly quote": "\u201c"}


def fetch_issue(number: int) -> dict:
    """อ่าน issue จาก GitHub"""
    out = subprocess.run(
        ["gh", "issue", "view", str(number), "--repo", REPO, "--json", "number,title,url,body"],
        capture_output=True,
        check=True,
    )
    return json.loads(out.stdout.decode("utf-8"))


def check_body(body: str) -> dict[str, bool]:
    """ตรวจเงื่อนไขที่ issue ต้องผ่าน"""
    checks = {f"has {h}": h in body for h in REQUIRED_HEADINGS}
    checks["has 4 layer sections"] = body.count("### ชั้นที่") == 4
    checks["has 6-item proof table"] = "## ผลการพิสูจน์ข้อสังเกต 6 ข้อ" in body
    checks["has todo section"] = "## งานที่ยังไม่ได้ทำ" in body
    checks["single actor name"] = body.count("ผม") >= 10 and "เรา" not in body
    for label, char in FORBIDDEN_CHARS.items():
        checks[f"no {label}"] = char not in body
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="ตรวจรูปแบบ issue บน GitHub")
    parser.add_argument("number", type=int, help="หมายเลข issue")
    args = parser.parse_args()

    data = fetch_issue(args.number)
    body = data["body"]
    checks = check_body(body)

    print(f"issue: {data['number']} {data['url']}")
    print(f"title: {data['title']}")
    print(f"body chars: {len(body)}")
    print()

    for name, ok in checks.items():
        print(("OK   " if ok else "FAIL ") + name)

    failed = [name for name, ok in checks.items() if not ok]
    print()
    if failed:
        print(f"{len(failed)} checks failed: {', '.join(failed)}")
        return 1
    print(f"all {len(checks)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
