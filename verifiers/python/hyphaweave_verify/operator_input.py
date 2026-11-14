# SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
# SPDX-License-Identifier: Apache-2.0

"""§14.1 operator inputs: path kinds and bounded reads (S1-FIX5 X3).

``--keys``, ``--tsa-trust`` and ``--previous`` name paths the operator supplies.
Before any of them is opened, its kind is established with ``lstat``: a symbolic
link is followed to its target, and the target must be a regular file or a
directory as the option requires. A FIFO, a character or block device, a socket
or anything else is a usage error (exit 2, no report) -- opening a FIFO for
reading would block the verifier indefinitely. A file that is read is read with
an explicit bound, and a file above the bound is a usage error as well.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import UsageError

FILE = "regular file"
DIRECTORY = "directory"


def path_kind(path: Path, option: str, *, allowed: tuple[str, ...]) -> str:
    """Return ``FILE`` or ``DIRECTORY`` for ``path``, or raise :class:`UsageError`.

    ``lstat`` decides first; a symbolic link is resolved (``stat``) and its
    target judged the same way, so a dangling link is a usage error too.
    """
    try:
        status = os.lstat(path)
    except FileNotFoundError as error:
        raise UsageError("%s %s does not exist" % (option, path)) from error
    except OSError as error:
        raise UsageError(
            "%s %s cannot be examined: %s" % (option, path, error.strerror or error)
        ) from error
    if stat.S_ISLNK(status.st_mode):
        try:
            status = os.stat(path)
        except OSError as error:
            raise UsageError(
                "%s %s is a symbolic link that does not resolve" % (option, path)
            ) from error
    if stat.S_ISREG(status.st_mode):
        kind = FILE
    elif stat.S_ISDIR(status.st_mode):
        kind = DIRECTORY
    else:
        raise UsageError(
            "%s %s is not a regular file or directory (a FIFO, device or socket is "
            "not accepted)" % (option, path)
        )
    if kind not in allowed:
        raise UsageError("%s %s is not a %s" % (option, path, " or ".join(allowed)))
    return kind


def read_bounded_file(path: Path, option: str, limit: int) -> bytes:
    """Read a regular operator file of at most ``limit`` bytes, or raise UsageError."""
    path_kind(path, option, allowed=(FILE,))
    try:
        # O_NONBLOCK: should the path have been replaced by a FIFO after the
        # check above, the open still returns instead of waiting for a writer,
        # and the fstat below rejects it.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise UsageError("%s %s is not a regular file" % (option, path))
            data = handle.read(limit + 1)
    except OSError as error:
        raise UsageError(
            "%s %s cannot be read: %s" % (option, path, error.strerror or error)
        ) from error
    if len(data) > limit:
        raise UsageError("%s %s is larger than %d bytes" % (option, path, limit))
    return data
