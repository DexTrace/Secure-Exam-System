# Module 10 — Administration and System Health

`Views/AdministrationDashboard` provides an administrator-only health and recovery view. Its module-specific `Services/ApiClient.Module10.cs` calls the protected API health and backup routes, and `Models/SystemAdministrationModels.cs` contains their response models.

Account and role administration remains in the shared **User accounts** page, and centre/room/device assignment remains in **Workstations**. Server policy values are read-only here; change environment-based API policies on the host and restart the API. Software updates use trusted signed releases; this app does not download or execute updates.
