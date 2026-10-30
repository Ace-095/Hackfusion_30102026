"""Run the real pytest suite and publish failure details as CI annotations.

The exit status is always pytest's; this helper never turns failures into passes.
"""
import subprocess
import sys
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET


def annotate(text: str) -> None:
    # GitHub workflow command escaping; cap annotation size and make output
    # console-safe on Windows even when the test contains non-ASCII text.
    text = text[:12000].encode("ascii", "backslashreplace").decode("ascii")
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title=Pytest failure::{text}", flush=True)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "pytest.xml"
        result = subprocess.run([sys.executable, "-m", "pytest", "-q", f"--junitxml={report}"], check=False)
        if result.returncode and report.exists():
            try:
                tree = ET.parse(report)
                for case in tree.iter("testcase"):
                    for problem in list(case.findall("failure")) + list(case.findall("error")):
                        annotate(f"{case.get('classname', '')}.{case.get('name', '')}\n{problem.text or problem.get('message', '')}")
            except (OSError, ET.ParseError):
                annotate("Unable to parse pytest's failure report; see job log.")
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
