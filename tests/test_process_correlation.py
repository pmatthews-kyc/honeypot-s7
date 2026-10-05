"""
test_process_correlation.py
------------------------------
Two tests:
1. Direct math correctness -- given a known current_values snapshot,
   confirm ProcessTag.step()'s influence term matches the formula
   exactly. Deterministic, no statistics involved.
2. Correlation direction over many ticks -- run two simulations that are
   identical except one has flow_rate pinned high and the other pinned
   low, and confirm tank_level trends measurably higher in the
   high-flow run. This is the actual behavior the correlation feature
   exists to produce: multiple tags moving together, not just each
   tag's own math being individually correct.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "src"))

import random

from process_simulator import ProcessTag


def test_influence_math_is_exact():
    random.seed(0)

    tag = ProcessTag(
        name="tank_level", db_number=1, offset=0,
        min_value=0.0, max_value=1000.0,  # wide bounds so clamping doesn't interfere
        max_step=0.0,                      # zero own-randomness, isolates the influence term
        setpoint=None, setpoint_gravity=0.0,
        influenced_by=[{"source": "flow_rate", "reference": 12.0, "coefficient": 0.05}],
    )
    tag.value = 50.0

    # flow_rate at 20.0, reference 12.0 -> expected delta = (20.0-12.0)*0.05 = 0.4
    new_value = tag.step(current_values={"flow_rate": 20.0})
    assert abs(new_value - 50.4) < 1e-9, f"expected exactly 50.4, got {new_value}"
    print(f"Influence math exact with own-randomness zeroed out: {new_value} == 50.4 -- OK")

    # flow_rate below reference should push the OTHER direction
    tag2 = ProcessTag(
        name="tank_level", db_number=1, offset=0,
        min_value=0.0, max_value=1000.0, max_step=0.0,
        influenced_by=[{"source": "flow_rate", "reference": 12.0, "coefficient": 0.05}],
    )
    tag2.value = 50.0
    new_value2 = tag2.step(current_values={"flow_rate": 4.0})
    # (4.0 - 12.0) * 0.05 = -0.4
    assert abs(new_value2 - 49.6) < 1e-9, f"expected exactly 49.6, got {new_value2}"
    print(f"Influence math correctly negative when source below reference: {new_value2} == 49.6 -- OK")


def _run_simulation(ticks: int, pinned_flow_value: float, seed: int) -> float:
    """Run tank_level for `ticks` iterations against a pinned (not
    stepped) flow_rate value, using the exact coefficients from
    config.yaml, and return the final tank_level value."""
    random.seed(seed)

    tank_level = ProcessTag(
        name="tank_level", db_number=1, offset=0,
        min_value=10.0, max_value=90.0, max_step=0.8,
        setpoint=55.0, setpoint_gravity=0.03,
        event_chance=0.0,  # disable random events for a cleaner comparison
        influenced_by=[{"source": "flow_rate", "reference": 12.0, "coefficient": 0.03}],
    )
    tank_level.value = 55.0  # start both runs from the same point

    for _ in range(ticks):
        tank_level.step(current_values={"flow_rate": pinned_flow_value})

    return tank_level.value


def test_correlation_direction_holds_over_many_ticks():
    """With flow_rate pinned high vs. pinned low (using config.yaml's
    actual reference=12.0, coefficient=0.03), tank_level must end up
    measurably higher in the high-flow run -- proving the tags actually
    move together rather than drifting independently, which is the
    whole point of this feature."""
    ticks = 200

    high_flow_result = _run_simulation(ticks, pinned_flow_value=22.0, seed=42)
    low_flow_result = _run_simulation(ticks, pinned_flow_value=2.0, seed=42)

    print(f"After {ticks} ticks: high-flow tank_level={high_flow_result:.2f}, "
          f"low-flow tank_level={low_flow_result:.2f}")

    assert high_flow_result > low_flow_result, (
        f"high-flow run ({high_flow_result:.2f}) should end up higher than "
        f"low-flow run ({low_flow_result:.2f}) -- correlation isn't holding"
    )
    # Not just higher by noise -- expect a clear, meaningful separation
    # given 200 ticks at these coefficients.
    assert high_flow_result - low_flow_result > 5.0, (
        f"separation ({high_flow_result - low_flow_result:.2f}) is too small "
        f"to be a meaningful correlation effect, likely dominated by noise"
    )
    print(f"Correlation direction holds with clear separation "
          f"({high_flow_result - low_flow_result:.2f}) -- OK")


def test_no_influence_config_behaves_exactly_as_before():
    """Regression check: a tag with no influenced_by (or step() called
    with current_values=None) must behave identically to the original
    pre-correlation code -- this feature must be additive, not change
    existing behavior for tags that don't opt in."""
    random.seed(7)
    tag_a = ProcessTag(name="x", db_number=1, offset=0, min_value=0.0, max_value=100.0, max_step=1.0)
    val_a = tag_a.step()  # no current_values passed at all

    random.seed(7)
    tag_b = ProcessTag(name="x", db_number=1, offset=0, min_value=0.0, max_value=100.0, max_step=1.0)
    val_b = tag_b.step(current_values={"irrelevant": 999.0})  # unrelated snapshot present

    assert val_a == val_b, "a tag with no influenced_by must ignore any current_values passed in"
    print("Tags with no influenced_by are unaffected by correlation feature -- OK")


if __name__ == "__main__":
    test_influence_math_is_exact()
    test_correlation_direction_holds_over_many_ticks()
    test_no_influence_config_behaves_exactly_as_before()
    print("\nAll process correlation tests passed.")
