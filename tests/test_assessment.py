from assessment import TEMPLATES, build_assessment


def test_each_template_resolves_with_required_slots():
    for scenario in TEMPLATES:
        assessment = build_assessment(
            scenario,
            score="50%",
            confidence="80%",
            pattern="--drop",
        )

        assert isinstance(assessment, str)
        assert assessment


def test_unknown_scenario_returns_fallback_with_scenario_name():
    assessment = build_assessment("UNKNOWN_SCENARIO")

    assert assessment == "Security assessment: UNKNOWN_SCENARIO."


def test_missing_slots_return_raw_template():
    assessment = build_assessment("HEURISTIC_BLOCK")

    assert assessment == TEMPLATES["HEURISTIC_BLOCK"]
