#!/usr/bin/env python3
# Portable guard for the "wrong Python" problem.
#
# gnuradio's Python bindings are compiled C++ extensions tied to whichever
# exact Python build they were installed against -- there is no single
# path that's correct on every machine (Homebrew on Apple Silicon uses
# /opt/homebrew, Homebrew on Intel Macs uses /usr/local, Linux/conda-forge
# installs put it somewhere else entirely). Hardcoding one absolute path
# in a shebang is NOT portable -- it only works on a machine laid out
# exactly like the one that path was written for, and fails with a
# confusing "bad interpreter" shell error (not even a Python traceback) on
# any other. So: keep shebangs as the normal portable `#!/usr/bin/env
# python3` (resolves via PATH like any other script), and call check()
# here, before importing anything that needs gnuradio, so a run under the
# wrong Python fails with a clear, actionable message instead of either a
# bare ModuleNotFoundError traceback or a shell-level path error.

import sys


def check() -> None:
    try:
        import gnuradio  # noqa: F401
    except ModuleNotFoundError:
        print("=" * 66, file=sys.stderr)
        print("ERROR: this script needs a Python build with GNU Radio installed.", file=sys.stderr)
        print(f"{sys.executable!r} does not have it.", file=sys.stderr)
        print("", file=sys.stderr)
        print("See PWNSAT-C3's INSTALL.md (github.com/Pwnsat/PWNSAT-C3) for the full install guide. Quick things", file=sys.stderr)
        print("to try:", file=sys.stderr)
        print("  which python3                 # is a gnuradio-capable Python on PATH?", file=sys.stderr)
        print("  /opt/homebrew/bin/python3 -c 'import gnuradio'   # Homebrew, Apple Silicon", file=sys.stderr)
        print("  /usr/local/bin/python3 -c 'import gnuradio'      # Homebrew, Intel Mac", file=sys.stderr)
        print("If one of those works, re-run this script with that exact interpreter:", file=sys.stderr)
        print(f"  <that python3 path> {sys.argv[0]}", file=sys.stderr)
        print("=" * 66, file=sys.stderr)
        sys.exit(1)
