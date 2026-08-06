"""Reading and normalising the host compatibility profile.

The profile is a flat `key = value` file. Keys are lowercase dotted names and
values are free-form single tokens or quoted strings. Blank lines and `#`
comments are ignored, surrounding whitespace is stripped, and a key that appears
more than once takes its last value -- the same tolerance the file has always
been read with, so that a hand-edited profile does not break a scheduled run.

`normalise()` produces the canonical form the rest of opsd works with: sorted
`key=value` lines with no whitespace and no comments. Everything that compares
two profiles compares that form, so cosmetic differences (ordering, spacing,
comments) never count as a change.
"""
import re

from .util import read

_LINE = re.compile(r"^\s*([a-z][a-z0-9._]*)\s*=\s*(.*?)\s*$")


class Profile(dict):
    """The active set of controls, as opsd resolved them."""

    @classmethod
    def load(cls, path):
        prof = cls()
        for line in read(path).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = _LINE.match(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            prof[key] = value
        return prof

    def control(self, key, default=""):
        """One control's value, or `default` if the profile does not set it.

        A control the profile does not carry -- or carries in terms this build
        does not recognise -- falls back to the legacy-compatible behaviour the
        host has always had, which is what each renderer's default branch is.
        """
        return self.get(key, default)

    def normalise(self):
        return "\n".join("%s=%s" % (k, self[k]) for k in sorted(self))


def normalise_file(path):
    """Canonical form of the profile stored at `path`."""
    return Profile.load(path).normalise()
