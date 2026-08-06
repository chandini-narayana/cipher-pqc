"""DetectionEvent and RiskEvent — the two records that flow through pipeline/.

Implemented in a later step. See docs/SDD.md Section 8 for intended shape:
- DetectionEvent: device, tls_version, key_size, pfs, entropy, port_risk,
  protocol_flag, timestamp
- RiskEvent: detection, risk_score, category, remediation, nist_reference
"""

# TODO: implement DetectionEvent, RiskEvent dataclasses (Step: models)
