import pytest

from app.scanners.vulns.cvss import (
    cvss3_base_score,
    normalize_advisory_severity,
    parse_cvss3_vector,
    severity_from_score,
    severity_rank,
)


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # Score confirmed against the NVD record for CVE-2024-47081 (tests/fixtures/vulns).
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_base_scores(vector, expected):
    assert cvss3_base_score(vector).base_score == expected


def test_version_reported():
    assert cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").version == "3.0"


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate
        "CVSS:3.1/AVN/AC:L",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/" + "X:Y/" * 100,
    ],
)
def test_invalid_vectors_raise(vector):
    with pytest.raises(ValueError):
        cvss3_base_score(vector)


def test_temporal_metrics_tolerated():
    m = parse_cvss3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P")
    assert m["E"] == "P"


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (None, "UNKNOWN"),
        (0, "NONE"),
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
    ],
)
def test_severity_bands(score, band):
    assert severity_from_score(score) == band


def test_advisory_label_mapping():
    assert normalize_advisory_severity("MODERATE") == "MEDIUM"
    assert normalize_advisory_severity("high") == "HIGH"
    assert normalize_advisory_severity("bogus") is None
    assert normalize_advisory_severity(5) is None
    assert severity_rank("CRITICAL") > severity_rank("LOW") > severity_rank("UNKNOWN")
