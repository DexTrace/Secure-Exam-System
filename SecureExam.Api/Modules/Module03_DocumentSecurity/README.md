# Module 3 — Document Security

This module's encrypted paper persistence and integrity verification are implemented in the shared `../Module02_QuestionPaperEditor/Data/PaperStore.cs`. That store is shared with paper editing and distribution so encryption, versioning, and access checks use one persistence path. Recipient-specific PDF watermarking and fingerprint tracing are in `../Module07_WatermarkLeakTracing/`.
