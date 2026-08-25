"""The index page across every class.

Its whole risk is one thing: an index is where "nothing here" and "nothing
looked" become indistinguishable. A class showing no findings reads as a clean
class, and a reader who was not told the leg failed will believe it. Every test
below is about refusing that, and none is about how the page looks.
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from source_analyst import records
from source_analyst.lifecycle import overview


def fact(file="A.java", line=20):
    return records.fact(
        {"kind": "flow", "subject": "p.C.h:R(S)", "object": "p.C.q:R(S)",
         "source_name": "q", "source_marker": "m", "source_origin": "annotation",
         "source_code": "x", "source_file": file, "source_line": 1,
         "sink_name": "s", "sink_full_name": "f", "sink_code": "c", "sink_arg_code": "a",
         "sink_file": file, "sink_line": line, "path_length": 2, "crosses_methods": 1,
         "path_count": 1, "steps": []}, "cpg:reachable")


def hyp(status="needs_proof"):
    return records.record("hypothesis", {
        "statement": "s", "vuln_class": "sqli", "status": status,
        "confidence": 0.7, "evidence": []}, src="agent:hypothesize")


def finding(sev="high", title="q reaches s at A.java:20"):
    return records.record("finding", {
        "hypothesis": "h_1", "title": title, "tier": "static_reachability",
        "severity": sev, "recreation": "…", "refs": [], "impact": "…",
        "caveats": []}, src="agent:report")


def gaps_section(out: str) -> str:
    """Just the 'not assessed' block. Any fixture names one class, and the other
    manifest classes correctly appear as gaps, so an assertion about the class
    under test has to look here rather than at the whole page."""
    if "what was not assessed" not in out:
        return ""
    return out.split("what was not assessed", 1)[1].split("## Classes", 1)[0]


class TestNothingLookedIsNotNothingFound(unittest.TestCase):
    def render(self, logs: dict[str, list[dict]]) -> str:
        d = Path(tempfile.mkdtemp())
        for name, recs in logs.items():
            (d / f"{name}.log.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in recs))
        buf = io.StringIO()
        with redirect_stdout(buf):
            overview.main(["--logs", str(d), "--target", "T"])
        return buf.getvalue()

    def test_facts_but_no_judgement_is_flagged_not_shown_as_clean(self):
        out = self.render({"sqli": [fact()]})
        self.assertIn("SQL injection", gaps_section(out))
        self.assertIn("hypothesize leg did not run", gaps_section(out))
        # and it must not be presented as a finished class
        self.assertNotIn("| 0 |", out)

    def test_empty_log_is_flagged(self):
        out = self.render({"sqli": []})
        self.assertIn("SQL injection", gaps_section(out))

    def test_judged_and_all_refuted_is_an_answer_not_a_gap(self):
        """Refuting every candidate IS a result, and must not be filed as a gap."""
        out = self.render({"sqli": [fact(), hyp("refuted")]})
        self.assertNotIn("SQL injection", gaps_section(out))
        self.assertIn("all candidates refuted", out)

    def test_reported_class_links_to_its_report(self):
        out = self.render({"sqli": [fact(), hyp(), finding()]})
        self.assertIn("sqli.report.md", out)
        self.assertIn("high", out)
        self.assertNotIn("SQL injection", gaps_section(out))

    def test_a_class_with_no_log_at_all_still_gets_a_row(self):
        """The same failure one level up: a class absent from the directory would
        simply not appear, and a page that never mentions a class cannot warn
        about it. Rows come from the manifest, not from whatever files exist."""
        out = self.render({"sqli": [fact(), hyp(), finding()]})
        for other in ("Path traversal", "Open redirect"):
            self.assertIn(other, out)
        self.assertIn("the run never reached it", out)

    def test_an_index_over_nothing_is_refused(self):
        d = Path(tempfile.mkdtemp())
        with self.assertRaises(SystemExit):
            overview.main(["--logs", str(d), "--target", "T"])


class TestAddsNothing(unittest.TestCase):
    """render's contract, inherited: reformat records, invent nothing."""

    def render(self, recs):
        d = Path(tempfile.mkdtemp())
        (d / "sqli.log.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
        buf = io.StringIO()
        with redirect_stdout(buf):
            overview.main(["--logs", str(d), "--target", "T"])
        return buf.getvalue()

    def test_severity_is_the_agents_not_the_pages(self):
        out = self.render([fact(), hyp(), finding(sev="low")])
        self.assertIn("low", out)
        for invented in ("critical", "high", "medium"):
            self.assertNotIn(f"**{invented}**", out)

    def test_never_claims_confirmation(self):
        out = self.render([fact(), hyp(), finding()])
        self.assertIn("Nothing on this page is confirmed", out)
        self.assertNotIn("confirmed vulnerability", out.lower())

    def test_long_title_is_shortened_without_losing_the_count(self):
        recs = [fact(), hyp()] + [finding(title=f"finding number {i} " + "x" * 200)
                                  for i in range(overview.PREVIEW + 3)]
        out = self.render(recs)
        self.assertIn("…and 3 more", out)
        self.assertNotIn("x" * 150, out)


if __name__ == "__main__":
    unittest.main()
