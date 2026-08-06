"""CipherError hierarchy (see docs/SDD.md Section 12):

CipherError (base)
├── CaptureError
│   └── LiveCaptureNotImplementedError   # raised by capture.live_source (D2)
├── ParsingError
├── RiskEngineError
├── ModelNotFoundError                    # triggers ml D4 fallback
├── SigningError
└── ReportGenerationError

Implemented in a later step.
"""

# TODO: implement exception hierarchy (Step: utils)
