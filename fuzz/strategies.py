"""Hypothesis pieces shared by the property harnesses: settings, text, JSON values."""
import json
import sys

try:
    from hypothesis import HealthCheck, strategies as st
except ImportError:
    sys.exit("fuzz: Hypothesis is not installed. pip install '.[fuzz]'")

from common import N

# database=None: nothing is written next to the harness. Reproduce a run with
# FUZZ_SEED instead (common.main applies it).
SET = dict(max_examples=N, deadline=None, database=None, suppress_health_check=list(HealthCheck))

# Text a server could put anywhere: empty, almost-numbers, path tricks, a BOM,
# a NUL, a lone surrogate, Arabic-Indic digits (str.isdigit() is true for them).
texts = st.one_of(
    st.sampled_from(["", " ", "0", "1", "true", "null", "ok", "..", "/", "\\", "NUL", "a\n",
                     "﻿", "\x00", "%00", "id", "next", "error", "Method not found",
                     "QUJD", "3082", "MIIB", "0x10", "١٢٣", "\ud800"]),
    st.text(max_size=12),
    st.text(alphabet="0123456789abcdefABCDEF", max_size=40),
)
_scalar = st.one_of(
    st.none(), st.booleans(), st.integers(-3, 70000), st.integers(),
    st.floats(allow_nan=True, allow_infinity=True), texts,
)


def json_values(leaf=_scalar, max_leaves=8):
    return st.recursive(
        leaf,
        lambda kids: st.one_of(st.lists(kids, max_size=4),
                               st.dictionaries(texts, kids, max_size=4)),
        max_leaves=max_leaves)


JSON = json_values()


def mostly(good, bad=JSON, odds=6):
    """The valid shape most of the time: one wrong value must not be drowned by five others."""
    return st.one_of(*([good] * odds), bad)


def dumps(value) -> str:
    """JSON text the way a server could send it (NaN / Infinity, lone surrogates as escapes)."""
    return json.dumps(value, ensure_ascii=True, allow_nan=True)
