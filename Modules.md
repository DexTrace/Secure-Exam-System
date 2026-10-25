# Module source map

The API and WPF client remain single runnable projects. Their shared startup and app-shell files stay at the project roots; feature implementation is grouped under each project's `Modules` directory. C# namespaces are unchanged, so this is a source-organization change rather than a runtime redesign.

| Module | API source | Desktop source |
|---|---|---|
| 1 — Authentication and roles | `SecureExam.Api/Modules/Module01_AuthenticationRoleManagement/` | `SecureExam.Desktop/Modules/Module01_AuthenticationRoleManagement/` |
| 2 — Question paper editor | `SecureExam.Api/Modules/Module02_QuestionPaperEditor/` | `SecureExam.Desktop/Modules/Module02_QuestionPaperEditor/` |
| 3 — Document security | Encrypted paper storage and integrity checks are in the shared `PaperStore` with Module 2; see `SecureExam.Api/Modules/Module03_DocumentSecurity/README.md`. | Shares the paper workflow and export UI; see `SecureExam.Desktop/Modules/Module03_DocumentSecurity/README.md`. |
| 4 — Secure workstation | Workstation persistence is part of the shared authentication store; see `SecureExam.Api/Modules/Module04_SecureWorkstation/README.md`. | `SecureExam.Desktop/Modules/Module04_SecureWorkstation/` |
| 5 — Audit logging | `SecureExam.Api/Modules/Module05_AuditLogging/` | The audit screen is part of the shared app shell; see `SecureExam.Desktop/Modules/Module05_AuditLogging/README.md`. |
| 6 — Approval and distribution | Grant and issuance persistence is part of the shared paper workflow store; see `SecureExam.Api/Modules/Module06_ApprovalDistribution/README.md`. | Distribution UI is part of the paper workspace and app shell; see `SecureExam.Desktop/Modules/Module06_ApprovalDistribution/README.md`. |
| 7 — Watermark and leak tracing | `SecureExam.Api/Modules/Module07_WatermarkLeakTracing/` | `SecureExam.Desktop/Modules/Module07_WatermarkLeakTracing/` |
| 8 — Investigation dashboard | `SecureExam.Api/Modules/Module08_InvestigationDashboard/` | `SecureExam.Desktop/Modules/Module08_InvestigationDashboard/` |
| 9 — Alerts and incidents | `SecureExam.Api/Modules/Module09_AlertIncidentManagement/` | `SecureExam.Desktop/Modules/Module09_AlertIncidentManagement/` |
| 10 — Administration and system health | `SecureExam.Api/Modules/Module10_AdministrationSystemHealth/` | `SecureExam.Desktop/Modules/Module10_AdministrationSystemHealth/` |

`SecureExam.Api/Program.cs`, `SecureExam.Desktop/MainWindow.xaml`, and `SecureExam.Desktop/MainWindow.xaml.cs` are intentionally shared entry points: they register and connect the modules and provide common navigation, authentication, and audit UI. `SecureExam.Desktop/Services/ApiClient.cs` is the shared HTTP client; module-specific API client extensions are in their corresponding module folders.

Modules 2, 3, and 6 currently share `PaperStore` because editing, encrypted storage, review, grants, and copy issuance operate on the same persisted paper lifecycle. The folder notes identify these cross-module responsibilities rather than duplicating the store or creating misleading parallel implementations.
