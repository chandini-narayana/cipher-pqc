"""Superseded — see docs/SDD.md Step 4 addendum.

The original SDD draft planned a DetectionEvent/RiskEvent pair here.
Step 4's architecture freeze replaced that with a more granular set of
models matching the frozen pipeline (Packet -> Fingerprint -> Entropy
-> Device Features -> Risk Assessment / Anomaly Assessment -> Device
Assessment):

    PacketMetadata, ProtocolFingerprint, EntropyMetrics,
    DeviceFeatures, RiskAssessment, AnomalyAssessment, DeviceAssessment

This file is kept (rather than deleted) purely as a pointer for anyone
who goes looking for the models the original SDD text described.
Nothing imports from this module; it is not re-exported by
models/__init__.py.
"""