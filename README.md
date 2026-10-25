# Secure Exam System Desktop

Modules 1–10 are implemented as a native C# WPF client backed by a C# ASP.NET Core API and a SQLite database. Run the API and desktop client as separate processes.

## Source organization

Module-specific implementation is grouped in `Modules/ModuleXX_.../` under both `SecureExam.Api` and `SecureExam.Desktop`. The runnable projects and shared entry points remain unchanged. Some related features share persistence or UI files; [Modules.md](Modules.md) maps those shared responsibilities and all module folders.

## Administration and system health

Administrators can open **Administration & health** to verify API connectivity, run a SQLite integrity check, see account/device counts and effective security settings, and create a recovery backup on the API host. Existing **User accounts** and **Workstations** screens manage roles, accounts, device approval, and centre/room/workstation assignment.

Configure backup storage and retention before starting the API:

```powershell
$env:SECURE_EXAM_BACKUP_DIR = "C:\SecureExam\Backups"
$env:SECURE_EXAM_BACKUP_RETENTION_COUNT = "10"
```

The backup contains a consistent SQLite database and the complete Data Protection key ring. It is a sensitive, **unencrypted archive**; restrict the backup directory and its backups with server-side access controls, and protect off-host copies using an approved encrypted backup system. If `SECURE_EXAM_BACKUP_DIR` is omitted, backups are stored in the data directory's `backups` subfolder. The retention setting keeps the newest 1–100 archives (default 10). Audit records are append-only and are never automatically pruned.

Policy settings such as `SECURE_EXAM_REQUIRE_COMPLIANT_WORKSTATION` and data-protection certificate settings are configured in the API service environment and take effect after restart. This dashboard reports effective settings; it does not modify a running server's environment. Recovery must be performed offline: stop the API, restore the database and matching key ring together, restore any required key-encryption certificate private key, then restart and verify the system. Never overwrite the live database while the API is running.

## Requirements

- Windows 10/11 for the WPF desktop client.
- .NET 6 SDK.
- An authenticator app that supports time-based one-time passwords (TOTP).

The API can also run on Linux for development, but the WPF UI itself requires Windows. Running the published Windows client through Wine is not a supported production configuration.

## First-time setup on Windows

Open PowerShell in the `desktop` directory. Configure the initial administrator credentials before the API's first start; use a password of at least 14 characters containing letters and digits. These values create the administrator only if the database has no users.

```powershell
$env:SECURE_EXAM_ADMIN_EMAIL = "admin@example.com"
$env:SECURE_EXAM_ADMIN_PASSWORD = Read-Host "Initial administrator password"
$env:SECURE_EXAM_ADMIN_NAME = "System Administrator"
```

Enter the password at the prompt; keep it out of saved scripts and clear the variables after first setup with `Remove-Item Env:SECURE_EXAM_ADMIN_PASSWORD`.

Start the API in this terminal:

```powershell
dotnet run --project .\SecureExam.Api\SecureExam.Api.csproj
```

It listens on `http://127.0.0.1:5188` by default. By default, the API creates its SQLite database and data-protection keys in a `data` directory under the API process's application base directory (for example, the build output directory when using `dotnet run`, or the publish directory for a published executable). This default can be lost when build or publish output is replaced. Set `SECURE_EXAM_DATA_DIR` to a persistent location before starting the API, and keep that directory when restarting or upgrading the service:

```powershell
$env:SECURE_EXAM_DATA_DIR = "C:\SecureExam\Data"
```

In a second PowerShell terminal, from `desktop`, start the client:

```powershell
dotnet run --project .\SecureExam.Desktop\SecureExam.Desktop.csproj
```

The client connects to the local API by default. To use a different API URL, set `SECURE_EXAM_API_URL`; non-loopback endpoints must use HTTPS. The API's listen URL can be changed with `SECURE_EXAM_LISTEN_URL`, but it intentionally refuses non-loopback addresses.

## Sign-in and device setup

1. Sign in using the initial administrator email and password.
2. On first sign-in, add the displayed setup key to an authenticator app, then enter its current six-digit code.
3. The initial administrator's first workstation is approved automatically. Other workstations are pending until an administrator approves them from **Devices**.
4. Use **Users** to create accounts with the Admin, Paper Setter, Reviewer, or Investigator role. New users must enroll in MFA and have their workstation approved before they can sign in.
5. In **Workstations**, assign each computer a centre, room, and workstation ID before using it for an exam.

The app includes sign-in, MFA enrollment and verification, logout, session-expiry handling, password changes, user creation and role/status management, and workstation approval/revocation and location assignment. On sign-in, the client reports Windows policy indicators: enforced AppLocker executable rules or a WDAC policy file, and a configured system restriction (DisableCMD or DisableTaskMgr). Admins see the latest check and its results in **Workstations**. The Question papers workspace provides rich-text editing (bold, italic, underline), subject and exam metadata, sections and marks, instructions, automatic draft saving, version history, submission, reviewer approval/rejection/change requests, and read-only approved-paper viewing. Admins authorize distribution recipients and can expire or revoke access in **Distribution**. Every paper view, export, or print issuance is recorded with its own unique copy ID; Module 7 generates recipient-specific, version-bound watermarked PDFs and records each PDF's SHA-256 fingerprint. Admins and investigators can verify an unchanged recovered PDF in **Verify recovered PDF** and use the **Investigation** dashboard to search paper, copy, and incident IDs, inspect linked activity and workstation locations, and export an evidence report including known gaps and limitations. The **Alerts & incidents** dashboard detects security signals, supports investigator review and incident cases, and records reviewer/resolver identity. Admins can review the **Audit log** and verify its hash chain.

## Alert and incident management

Security alerts are generated from server-observed events: five or more failed password/MFA attempts from the same API connection address in 15 minutes; denied protected API requests; denied paper exports; sign-in completed on a workstation awaiting approval; and three or more successful exports by the same account for the same paper in 15 minutes. Repeated signals are deduplicated for 15 minutes. The remote address is the API connection peer and is not treated as a trusted identity. This initial detector is event/rule based; it does not classify intent or send out-of-band notifications.

Administrators and investigators can review alerts, create linked incident cases, and resolve alerts with a required note. Alert records, cases, and review/resolution actions are append-only at the SQLite layer. The dashboard records reviewer and resolver name, user ID, time, and notes; resolved alerts cannot be changed or reopened in this version. Alert creation and action endpoints are authenticated and role-checked by the API. Alerts and cases remain in the configured SQLite database and need the same protected backup/retention controls.

Alert API routes:

- `GET /api/alerts?status=open|reviewed|resolved` lists alerts and cases for administrators and investigators.
- `POST /api/alerts/{alertId}/review` records the reviewer and optional note.
- `POST /api/alerts/{alertId}/resolve` requires a resolution note and records the resolver.
- `POST /api/alerts/{alertId}/cases` creates an append-only incident case linked to the alert.

## Approval and distribution

Setters submit drafts for review. Reviewers can approve, reject with a required reason, or request changes with a note; a rejected/returned paper is sent back to the setter for revision and resubmission. Only approved papers can be granted to recipients. Administrators select the approved paper and active recipient account, optionally set a future expiry, and may revoke an active grant at any time. The API checks the current grant on paper listing, viewing, export, and print, so expiry/revocation takes effect immediately for subsequent requests. Administrators retain oversight access.

Each view, export, and print request creates a separate immutable issued-copy record with a cryptographically random unique ID and content SHA-256. Module 7 PDF exports repeat a controlled watermark containing the recipient name/email and copy ID, and link the PDF fingerprint to the issued copy, paper version, and recipient. The ID identifies an issuance record; it cannot prevent copying or prove that a physical printer completed a job.

## Watermarking and leak tracing

Recipients with an active grant can export approved papers as PDF. Each PDF is watermarked with the recipient identity and unique copy ID, and records its paper ID/version, recipient, content digest, server issuance time, and SHA-256 digest of the exact PDF bytes in an append-only fingerprint table. An administrator or investigator can select **Verify recovered PDF** and upload a recovered PDF (maximum 25 MB); the API returns the issuance record only for an exact fingerprint match. Modified PDFs, screenshots, and scanned/printed copies are not recognized by this exact-file fingerprint workflow; no OCR or forensic image matching is implemented.

API routes:

- `POST /api/papers/{paperId}/watermarked-copy` returns an authorized recipient-specific PDF and records its PDF fingerprint.
- `POST /api/document-tracing/verify` accepts a multipart `document` PDF and is restricted to administrators and investigators. Unknown fingerprints return a non-match; the original PDF is not saved by the verifier.

## Investigation dashboard

The **Investigation** workspace is available to administrators and investigators. It supports exact searches by paper ID, issued copy ID, or incident ID. Investigators can register an incident summary and link it to a known paper or issued copy; incident records are append-only and receive a generated ID. Reports include matching issuance records, associated paper audit history, the current registered workstation name/centre/room/workstation assignment, audit-chain verification status, and explicitly listed missing evidence and limitations. Reports can be exported as JSON to a user-selected location and may contain recipient names, email addresses, device identifiers, and audit data, so handle them as sensitive evidence.

The report identifies current device location assignments, not historical changes; evidence outside this database is not collected. Incident descriptions are user-entered and are not independently verified. Incident rows have database-level append-only guards but no independent integrity anchor. The audit chain is verified against the current database but is not anchored independently. An event proves the recorded request, not a human action or completed print. Workstation identity/compliance is not hardware attestation. PDF matching is exact-byte SHA-256 only and does not identify altered, scanned, or photographed copies. Exported JSON reports are unsigned and can be altered after export; the report does not establish evidence custody or completeness.

Investigation API routes:

- `GET /api/investigations/search?type=paper|copy|incident&query={id}` returns a report for administrators and investigators.
- `POST /api/investigations/incidents` registers a linked incident summary for administrators and investigators. Provide `summary` and at least one of `paperId` or `copyId`; a supplied copy ID must exist and determines its paper.

## Audit logging

The API writes a server-timestamped event for login/MFA attempts, logout, paper views and edits, submission, approval/change requests, export, print, and denied API access. Records include the authenticated user when known and the registered workstation identity. The ledger is append-only through SQLite update/delete guards and links each canonical event to the prior event hash. Administrators can view recent events in the desktop **Audit log**; the API retains all events and provides a full-chain verification endpoint.

The hash chain detects changed, reordered, or internally removed events when verified. It is not a substitute for a separately controlled immutable backup: a database administrator who can rewrite the database can also recompute an unkeyed hash chain or truncate its tail. For stronger tamper evidence, periodically export/anchor the latest sequence and hash to a separately administered immutable log or WORM storage. Audit details intentionally exclude request bodies, passwords, MFA codes, paper content, and export content.

## Workstation policies

Workstations are registered using a per-Windows-user device identity protected by DPAPI. An administrator must approve each new computer, assign its centre, room, and workstation ID, and revoke it when it is lost or retired. The server revalidates approval on protected requests.

The desktop app does not disable keys, intercept typing, or enforce OS restrictions. Apply application allow-listing and system restrictions separately using centrally managed Windows policy (for example, AppLocker or WDAC plus Group Policy). The WDAC check detects a policy file but cannot determine remotely whether that policy is in enforcement or audit mode. All compliance indicators are sign-in-time client reports, not tamper-resistant device attestation; a modified client can falsify them. Use domain/MDM management and endpoint security controls as the enforcement authority.

To reject sign-ins from workstations that do not report all required indicators, enable this on the API service:

```powershell
$env:SECURE_EXAM_REQUIRE_COMPLIANT_WORKSTATION = "true"
```

The default is `false` for development and migration. In enforcement mode, the API denies sign-in and invalidates sessions when a workstation has not reported all required policy indicators. This is a supplemental client-reported gate, not a substitute for Windows enforcement. Ensure an administrator has a policy-compliant approved workstation before enabling it.

Paper permissions are enforced by the API: setters can edit their own drafts, reviewers can review submitted papers, and approved papers are visible read-only. Administrators can manage all papers. A paper's section marks must add up to its total before it can be saved. Autosaved drafts and each workflow transition are recorded in version history in the SQLite database.

Paper API routes:

- `GET /api/papers` lists papers visible to the signed-in role.
- `POST /api/papers` creates a draft; `PUT /api/papers/{paperId}` saves an editable draft.
- `GET /api/papers/{paperId}` and `GET /api/papers/{paperId}/versions` read accessible paper data and history.
- `POST /api/papers/{paperId}/transition` accepts `submit`, `approve`, `reject` (requires a reason), or `request_changes`; server-side role and state checks apply.
- `POST /api/papers/{paperId}/export` and `/print` release content only for accessible, approved papers and record the access request with a content SHA-256 digest.
- `GET /api/papers/access-events` returns the latest 500 export/print events to administrators.
- `GET /api/papers/distribution-grants` lists grants; `POST` creates a grant for an active recipient and an approved paper; `PATCH /{grantId}/revoke` revokes active access. All require an administrator.
- `GET /api/papers/issued-copies` returns the latest 200 unique copy issuance records to administrators.

Audit API routes:

- `GET /api/audit/events?limit=200` returns up to 1,000 newest audit records to administrators.
- `GET /api/audit/verify` checks the complete sequence and hash chain and reports the first invalid sequence.

## Security and data notes

- Sessions expire after eight hours and are invalidated by logout, password changes, role changes, account disablement, MFA reset, or device revocation.
- Workstation location assignment and approval/revocation are server-authorized admin operations. The compliance report is refreshed on each MFA sign-in and is enforced when `SECURE_EXAM_REQUIRE_COMPLIANT_WORKSTATION=true`.
- Audit records use server-generated UTC timestamps, event hashes, and the authenticated session's registered device identity. Access to audit viewing and verification is restricted to administrators.
- Passwords are stored as PBKDF2-SHA256 hashes. TOTP secrets and device credentials are protected server-side; the Windows client protects its device identity with DPAPI.
- The API binds to loopback by default and requires HTTPS for remote client connections.
- Paper sections, instructions, rich-text content, and version snapshots are authenticated-encrypted before SQLite storage. Metadata used to list papers is bound to the encrypted payload and checked when read; tampering blocks access with an integrity error. Legacy plaintext paper rows are encrypted on API startup, scrubbed from live columns, and the database is checkpointed/vacuumed. This cannot erase copies in old backups, filesystem snapshots, or storage media.
- Paper titles, subjects, exam codes, status, and access-audit metadata remain plaintext in SQLite for listing and audit workflows; they are authenticated against the encrypted payload when a paper is opened. Restrict access to the entire data directory.
- Exported PDFs contain readable paper content and recipient-specific watermarks; the desktop writes the chosen PDF directly to the selected path. The verifier hashes uploaded bytes in memory and does not persist the recovered file. Printing is sent directly through Windows printing APIs without an application-created temporary document file. The API cannot verify whether a physical printer completed a job or determine the source of modified/scanned copies.
- **Protect the key ring for Windows deployment.** Without a certificate, the development setup stores ASP.NET Core Data Protection keys as files; paper encryption is only as secure as access to that key directory. Create/import a service-managed PFX certificate, then configure the API process:

  ```powershell
  $env:SECURE_EXAM_KEY_ENCRYPTION_CERT = "C:\SecureExam\keys\data-protection.pfx"
  $env:SECURE_EXAM_KEY_ENCRYPTION_CERT_PASSWORD = Read-Host "PFX password"
  $env:SECURE_EXAM_REQUIRE_PROTECTED_KEYS = "true"
  ```

  Use a production-managed certificate and secret store rather than a self-signed development certificate. The certificate must contain its private key. The key ring rotates Data Protection keys every 90 days; this does not rotate the certificate automatically.
- Certificate rotation: set the new PFX as `SECURE_EXAM_KEY_ENCRYPTION_CERT`; set `SECURE_EXAM_KEY_ENCRYPTION_CERT_PREVIOUS` to a semicolon-separated list of old PFX paths and `SECURE_EXAM_KEY_ENCRYPTION_CERT_PREVIOUS_PASSWORDS` to the matching semicolon-separated passwords. Restart and verify existing MFA secrets and papers can be read before retiring anything. Keep historical private keys available for as long as the key ring contains keys encrypted with them; simply removing an old certificate can make existing content unrecoverable.
- **Backup and recovery:** stop the API before taking a consistent backup. Securely copy the entire `SECURE_EXAM_DATA_DIR` (SQLite database plus every Data Protection key file) and the matching active/historical certificate private keys. Restore the data directory and those same certificates before starting the API. Never delete or regenerate the key ring to fix a decryption error; doing so makes encrypted MFA secrets and paper documents unrecoverable. Test recovery from a protected backup before production use.

## Build and publish

Build both projects from `desktop`:

```powershell
dotnet build .\SecureExam.Api\SecureExam.Api.csproj
dotnet build .\SecureExam.Desktop\SecureExam.Desktop.csproj
```

Publish a self-contained Windows x64 desktop build:

```powershell
dotnet publish .\SecureExam.Api\SecureExam.Api.csproj `
    -c Release -r win-x64 --self-contained true
dotnet publish .\SecureExam.Desktop\SecureExam.Desktop.csproj `
    -c Release -r win-x64 --self-contained true
```

Run the published API executable first, then run the published desktop application. They are separate processes; the desktop publish does not include or start the API.
