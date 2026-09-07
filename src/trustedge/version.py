"""Single source of truth for the TrustEdge version.

Kept in its own module so nothing has to import the package root (and risk a
circular import) just to read a version string.
"""

__version__ = "0.1.0"
