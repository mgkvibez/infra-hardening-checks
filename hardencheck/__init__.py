"""hardencheck: static hardening checks for the config people actually ship.

Every finding is bounded by a ruleset version: this tool reports what its rules
found, and says so, because "no findings" is not "no issues" and definitely not
"safe".
"""

__version__ = "0.1.0"
RULESET = "v1"
