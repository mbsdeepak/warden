"""warden: an agentic tool-call firewall.

A deterministic reference monitor between an LLM agent and its tools.
Every proposed tool call receives an allow / block / flag decision with a
human-readable reason. See DESIGN.md for the full design and decision log.
"""

__version__ = "0.1.0"
