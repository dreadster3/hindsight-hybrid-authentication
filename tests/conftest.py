"""Put the vendored ``hindsight_api`` stub on ``sys.path`` for the test run.

The extension ships into a Hindsight image at runtime; ``hindsight_api`` is not
a dependency of this repo. ``tests/_stub`` holds a verbatim copy of the pinned
upstream interface (vectorize-io/hindsight @ a9eeed77) so the extension is
exercised against the real contract rather than against a re-invented one.
"""

import sys
from pathlib import Path

_STUB_DIR = Path(__file__).parent / "_stub"
if str(_STUB_DIR) not in sys.path:
    sys.path.insert(0, str(_STUB_DIR))
