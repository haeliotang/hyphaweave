# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0
"""S2-FIX2 U4 (decision 2026-11-15 #22): the ISO 2022 escape-sequence rules of 1a.

The conformance vectors pin one case per rule inside a re-signed receipt; these unit
tests cover the escape-sequence forms the vectors do not spell out (multi-octet sets,
96-character sets, C0/C1 designations, sequences that are not designations).
"""

from __future__ import annotations

import pytest

from hyphaweave_verify import timestamps

ESC = b"\x1b"


@pytest.mark.parametrize(
    "tag, content, accepted",
    [
        # GraphicString (25): G0 6 assumed.
        (25, ESC + b"(B", False),  # re-designates 6 as G0
        (25, ESC + b"(uA" + ESC + b"(BA", True),  # 102 then 6 again
        (25, ESC + b"$BAA", True),  # 94^n set B into G0 (short form)
        (25, ESC + b"$(BAA", True),  # 94^n set B into G0 (long form)
        (25, ESC + b"$BAA" + ESC + b"$(B", False),  # the same 94^n entry again
        (25, ESC + b"$)BAA", False),  # 94^n set into G1: G0 is smaller
        (25, ESC + b"-AA", True),  # 96-character set A into G1, its smallest set
        (25, ESC + b"-A" + ESC + b".A", False),  # the same 96 set again, into G2
        (25, ESC + b".AA", False),  # 96-character set into G2: G1 is smaller
        (25, ESC + b"nA", True),  # LS2: not a designation, not judged
        (25, ESC + b" A", False),  # announcer
        (25, ESC, False),  # lone ESC
        (25, ESC + b"(", False),  # intermediate without final
        (25, ESC + b"(\x7f", False),  # DEL is not a final octet
        # GeneralString (27): G0 6 and C0 1 assumed.
        (27, ESC + b"!@", False),  # re-designates C0 1
        (27, ESC + b"!E", True),  # C0 106 is not designated
        # TeletexString (20): G0 102, C0 106, C1 107 assumed.
        (20, ESC + b"\"H", False),  # re-designates C1 107
        (20, ESC + b"\"A", True),  # C1 73
        (20, ESC + b"(BA", True),  # 6 into G0 (needed)
        # VideotexString (21): G0 102, C0 1, C1 73 assumed.
        (21, ESC + b"\"A", False),  # re-designates C1 73
        (21, ESC + b"!E", True),
        # ObjectDescriptor (7) is a GraphicString.
        (7, ESC + b"(uA", True),
    ],
)
def test_iso2022_escape_sequences(tag: int, content: bytes, accepted: bool) -> None:
    if accepted:
        timestamps._check_der_iso2022(tag, content)
    else:
        with pytest.raises(timestamps._DerViolation):
            timestamps._check_der_iso2022(tag, content)
