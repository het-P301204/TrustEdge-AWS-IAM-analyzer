"""TrustEdge - AWS inbound trust boundary analyzer.

Answers one question about an AWS account, offline, from an IAM export:

    Who outside this account can become an identity inside it, how strong is
    the condition guarding that door, and what do they get once through it?

Findings are ranked by ``exposure x blast radius`` so a weak door onto a
powerful role outranks both a strong door onto a powerful role and a weak door
onto a harmless one.

Typical use::

    from trustedge import analyze_file, render_markdown

    result = analyze_file("fixtures/sample-account.json")
    print(render_markdown(result))

TrustEdge makes no AWS API calls and requires no credentials.
"""

from __future__ import annotations

from .version import __version__

__all__ = [
    "__version__",
    "analyze",
    "analyze_file",
    "parse_export",
    "load_json_file",
    "ExportFormatError",
    "render_markdown",
    "render_html",
    "render_json",
]


def __getattr__(name):  # pragma: no cover - thin lazy-import shim
    """Import submodules on first use.

    Keeps ``import trustedge`` cheap and avoids any chance of a circular
    import between the package root and the analyser.
    """
    if name in ("analyze", "analyze_file"):
        from . import analyzer

        return getattr(analyzer, name)
    if name in ("parse_export", "load_json_file", "ExportFormatError"):
        from . import parser

        return getattr(parser, name)
    if name in ("render_markdown", "render_html", "render_json"):
        from . import report

        return getattr(report, name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
