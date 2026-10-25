# Module 10 — Administration and System Health

`Services/SystemAdministrationService.cs` provides authenticated administration health snapshots and server-side recovery backup creation. The admin-only routes are `GET /api/admin/system` and `POST /api/admin/system/backups`; both rely on the existing authenticated session and server-side administrator role check in the API host.

Health snapshots verify SQLite integrity and report connectivity, account/device counts, the effective compliance/key-protection policies, key-ring file count, API/runtime versions, and retained backup metadata. Backups use SQLite's online backup API and include the matching Data Protection key files. They are written on the API host, are not downloaded through the client, and are not encrypted by the application.

Configure `SECURE_EXAM_BACKUP_DIR` and `SECURE_EXAM_BACKUP_RETENTION_COUNT` in the API environment. The count is limited to 1–100 (default 10). Older generated archives are removed only after a new archive has been successfully created. Audit retention remains append-only and is not configurable for deletion. Restore only while the API is stopped; database, key ring, and any certificate private key must match.

User/role and workstation assignment management is in the existing administrator screens. Security policies are host-environment settings and require an API restart; software updates are deployed from a trusted signed release rather than downloaded or executed by the app. This release does not implement a database restore button, a dynamic centre registry, or automatic application updating.
