"""LiveCaptureSource — DOCUMENTED SCAFFOLD ONLY in Phase 1 (SDD D2).

This class will implement CaptureSource against a real network interface
via scapy.sniff() in a later phase of work. In Phase 1 it exists so the
interface, the factory wiring, and CAPTURE_MODE=live all have a real,
loudly-failing target rather than a silent gap.

read_packets() is implemented to immediately raise
LiveCaptureNotImplementedError (see utils/exceptions.py) rather than
returning an empty iterator, so a misconfigured CAPTURE_MODE=live fails
at startup, not as a quietly-empty dashboard later.

Implemented (as a scaffold) in a later step.
"""

# TODO: implement LiveCaptureSource(CaptureSource) that raises
# LiveCaptureNotImplementedError from read_packets() (Step: capture)
