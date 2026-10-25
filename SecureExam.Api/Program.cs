using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;
using SecureExam.Api.Data;
using SecureExam.Api.Models;
using SecureExam.Api.Security;
using SecureExam.Api.Services;

var builder = WebApplication.CreateBuilder(args);
var listenUrl = builder.Configuration["SECURE_EXAM_LISTEN_URL"] ?? "http://127.0.0.1:5188";
if (!Uri.TryCreate(listenUrl, UriKind.Absolute, out var listenUri) || !listenUri.IsLoopback)
{
    throw new InvalidOperationException("The authentication service must bind to localhost only.");
}

var keyDirectory = builder.Configuration["SECURE_EXAM_DATA_DIR"];
if (string.IsNullOrWhiteSpace(keyDirectory))
{
    keyDirectory = Path.Combine(AppContext.BaseDirectory, "data");
}

Directory.CreateDirectory(keyDirectory);
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("SecureExam.Authentication")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(keyDirectory, "keys")));
var certificatePath = builder.Configuration["SECURE_EXAM_KEY_ENCRYPTION_CERT"];
var keyCertificates = new List<X509Certificate2>();
if (!string.IsNullOrWhiteSpace(certificatePath))
{
    var certificatePassword = builder.Configuration["SECURE_EXAM_KEY_ENCRYPTION_CERT_PASSWORD"];
    var certificate = new X509Certificate2(
        certificatePath,
        certificatePassword,
        X509KeyStorageFlags.EphemeralKeySet);
    if (!certificate.HasPrivateKey)
    {
        throw new InvalidOperationException("The data-protection certificate must include its private key.");
    }

    keyCertificates.Add(certificate);
    var previousCertificatePaths = (builder.Configuration["SECURE_EXAM_KEY_ENCRYPTION_CERT_PREVIOUS"] ?? string.Empty)
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    var previousCertificatePasswordsSetting = builder.Configuration["SECURE_EXAM_KEY_ENCRYPTION_CERT_PREVIOUS_PASSWORDS"];
    var previousCertificatePasswords = string.IsNullOrEmpty(previousCertificatePasswordsSetting)
        ? Array.Empty<string>()
        : previousCertificatePasswordsSetting.Split(';', StringSplitOptions.None);
    if (previousCertificatePaths.Length != previousCertificatePasswords.Length)
    {
        throw new InvalidOperationException(
            "Configure one previous certificate password for each path in SECURE_EXAM_KEY_ENCRYPTION_CERT_PREVIOUS.");
    }

    foreach (var (previousPath, index) in previousCertificatePaths.Select((path, index) => (path, index)))
    {
        var previousCertificate = new X509Certificate2(
            previousPath,
            previousCertificatePasswords[index],
            X509KeyStorageFlags.EphemeralKeySet);
        if (!previousCertificate.HasPrivateKey)
        {
            throw new InvalidOperationException("Each previous data-protection certificate must include its private key.");
        }

        keyCertificates.Add(previousCertificate);
    }

    dataProtection.ProtectKeysWithCertificate(certificate);
    dataProtection.UnprotectKeysWithAnyCertificate(keyCertificates.ToArray());
}
else if (bool.TryParse(builder.Configuration["SECURE_EXAM_REQUIRE_PROTECTED_KEYS"], out var requireProtectedKeys) &&
         requireProtectedKeys)
{
    throw new InvalidOperationException(
        "SECURE_EXAM_REQUIRE_PROTECTED_KEYS is enabled but SECURE_EXAM_KEY_ENCRYPTION_CERT is not configured.");
}
else if (!string.IsNullOrWhiteSpace(builder.Configuration["SECURE_EXAM_KEY_ENCRYPTION_CERT_PREVIOUS"]))
{
    throw new InvalidOperationException(
        "Previous key-encryption certificates cannot be configured without an active SECURE_EXAM_KEY_ENCRYPTION_CERT.");
}

builder.Services.AddSingleton<AuthStore>();
builder.Services.AddSingleton<PaperStore>();
builder.Services.AddSingleton<DocumentFingerprintStore>();
builder.Services.AddSingleton<InvestigationStore>();
builder.Services.AddSingleton<InvestigationService>();
builder.Services.AddSingleton<AlertManagementStore>();
builder.Services.AddSingleton<WatermarkedPdfService>();
builder.Services.AddSingleton<AuditStore>();
builder.Services.AddSingleton<SystemAdministrationService>();
builder.Services.AddSingleton<LoginRateLimiter>();
builder.WebHost.UseUrls(listenUrl);

var app = builder.Build();
app.Lifetime.ApplicationStopped.Register(() =>
{
    foreach (var certificate in keyCertificates)
    {
        certificate.Dispose();
    }
});
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (PaperIntegrityException exception)
    {
        app.Logger.LogError(exception, "Encrypted paper integrity verification failed for {Path}.", context.Request.Path);
        if (context.Response.HasStarted)
        {
            throw;
        }

        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status409Conflict;
        context.Response.ContentType = "application/json";
        context.Response.Headers["Cache-Control"] = "no-store";
        await context.Response.WriteAsJsonAsync(
            new { error = "Paper integrity verification failed. The document cannot be opened." });
    }
});
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Cache-Control"] = "no-store";
    await next();
});

app.Use(async (context, next) =>
{
    if (!context.Request.Path.StartsWithSegments("/api"))
    {
        await next();
        return;
    }

    var path = context.Request.Path.Value ?? string.Empty;
    if (path == "/api/auth/login" || path.StartsWith("/api/auth/mfa/", StringComparison.Ordinal) ||
        path.EndsWith("/transition", StringComparison.Ordinal))
    {
        context.Request.EnableBuffering(bufferThreshold: 4096, bufferLimit: 8192);
    }

    try
    {
        await next();
    }
    catch
    {
        try
        {
            var failedClassification = await ClassifyAuditEventAsync(context);
            await context.RequestServices.GetRequiredService<AuditStore>().AppendAsync(
                "denied_access",
                (context.Items["SecureExam.Session"] as SessionIdentity)?.UserId,
                (context.Items["SecureExam.Session"] as SessionIdentity)?.DeviceId ?? failedClassification.WorkstationId,
                failedClassification.ResourceType,
                failedClassification.ResourceId,
                "error",
                $"{context.Request.Method} {context.Request.Path} · unhandled server error",
                CancellationToken.None);
        }
        catch (Exception auditException) when (auditException is SqliteException or IOException or InvalidOperationException)
        {
            app.Logger.LogCritical(auditException, "Could not append audit event for failed request {Path}.", context.Request.Path);
        }

        throw;
    }

    var audit = context.RequestServices.GetRequiredService<AuditStore>();
    var session = context.Items["SecureExam.Session"] as SessionIdentity;
    var classification = await ClassifyAuditEventAsync(context);
    var outcome = context.Response.StatusCode >= 400
        ? "denied"
        : context.Request.Path == "/api/auth/login"
            ? "mfa_required"
            : context.Request.Path.StartsWithSegments("/api/auth/mfa") &&
              context.Response.Headers["Set-Cookie"].Any(value =>
                  value?.StartsWith("secureExamSession=", StringComparison.Ordinal) == true)
                ? "authenticated"
                : "success";
    if (context.Response.StatusCode >= 400 && classification.EventType != "login")
    {
        classification = classification with { EventType = "denied_access" };
    }

    try
    {
        await audit.AppendAsync(
            classification.EventType,
            session?.UserId,
            session?.DeviceId ?? classification.WorkstationId,
            classification.ResourceType,
            classification.ResourceId,
            outcome,
            $"{context.Request.Method} {context.Request.Path}{classification.Details}",
            context.RequestAborted);
    }
    catch (Exception exception) when (exception is SqliteException or IOException or InvalidOperationException)
    {
        app.Logger.LogCritical(exception, "Could not append audit event for {Method} {Path}.",
            context.Request.Method, context.Request.Path);
        if (!context.Response.HasStarted)
        {
            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsJsonAsync(
                new { error = "The audit service is unavailable. The request could not be confirmed." },
                CancellationToken.None);
        }
    }

    try
    {
        var resourceId = classification.ResourceId;
        if (resourceId is null && context.Request.Path.StartsWithSegments("/api/papers"))
        {
            resourceId = context.Request.Path.Value?
                .Split('/', StringSplitOptions.RemoveEmptyEntries)
                .Skip(2)
                .FirstOrDefault();
        }

        await context.RequestServices.GetRequiredService<AlertManagementStore>().ObserveRequestAsync(
            context.Request.Path.Value ?? string.Empty,
            context.Response.StatusCode,
            session?.UserId,
            session?.DeviceId ?? classification.WorkstationId,
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            resourceId,
            DateTimeOffset.UtcNow,
            context.RequestAborted);
    }
    catch (Exception exception) when (exception is SqliteException or IOException or InvalidOperationException)
    {
        app.Logger.LogCritical(exception, "Could not evaluate security alerts for {Method} {Path}.",
            context.Request.Method, context.Request.Path);
    }
});

await using (var scope = app.Services.CreateAsyncScope())
{
    var store = scope.ServiceProvider.GetRequiredService<AuthStore>();
    await store.InitializeAsync();
    await scope.ServiceProvider.GetRequiredService<PaperStore>().InitializeAsync();
    await scope.ServiceProvider.GetRequiredService<InvestigationStore>().InitializeAsync(CancellationToken.None);
    await scope.ServiceProvider.GetRequiredService<AlertManagementStore>().InitializeAsync(CancellationToken.None);
    await scope.ServiceProvider.GetRequiredService<AuditStore>().InitializeAsync(CancellationToken.None);
    var email = Environment.GetEnvironmentVariable("SECURE_EXAM_ADMIN_EMAIL");
    var password = Environment.GetEnvironmentVariable("SECURE_EXAM_ADMIN_PASSWORD");
    var displayName = Environment.GetEnvironmentVariable("SECURE_EXAM_ADMIN_NAME") ?? "System Administrator";
    if (!await store.HasUsersAsync(CancellationToken.None) &&
        (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)))
    {
        throw new InvalidOperationException(
            "Configure SECURE_EXAM_ADMIN_EMAIL and SECURE_EXAM_ADMIN_PASSWORD before starting the API. " +
            "These values create the initial administrator only when the database is empty.");
    }

    if (!string.IsNullOrWhiteSpace(email) && !string.IsNullOrWhiteSpace(password))
    {
        await store.BootstrapAdministratorAsync(email, password, displayName, CancellationToken.None);
    }
}

app.Use(async (context, next) =>
{
    if (IsPublicEndpoint(context.Request.Path))
    {
        await next();
        return;
    }

    var store = context.RequestServices.GetRequiredService<AuthStore>();
    var token = context.Request.Cookies["secureExamSession"];
    if (string.IsNullOrEmpty(token))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { error = "Authentication required." });
        return;
    }

    var session = await store.GetSessionAsync(token, DateTimeOffset.UtcNow, context.RequestAborted);
    if (session is null)
    {
        context.Response.Cookies.Delete("secureExamSession");
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { error = "Session expired or revoked. Sign in again." });
        return;
    }

    context.Items["SecureExam.Session"] = session;
    await next();
});

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/api/admin/system", async (HttpContext context, SystemAdministrationService administration) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        return Results.Ok(new { system = await administration.GetSnapshotAsync(context.RequestAborted) });
    }
    catch (InvalidDataException exception)
    {
        app.Logger.LogError(exception, "System health check detected invalid database integrity.");
        return Results.Json(new { error = "The database integrity check failed. Do not create a backup until it is investigated." },
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch (SqliteException exception)
    {
        app.Logger.LogError(exception, "System health check could not connect to the database.");
        return Results.Json(new { error = "The database health check failed." },
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.MapPost("/api/admin/system/backups", async (
    HttpContext context,
    SystemAdministrationService administration) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var backup = await administration.CreateBackupAsync(context.RequestAborted);
        return Results.Created($"/api/admin/system/backups/{Uri.EscapeDataString(backup.FileName)}", new { backup });
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException)
    {
        app.Logger.LogError(exception, "Could not create a system recovery backup.");
        return Results.Json(new { error = "Backup creation failed. Check the API service's backup-directory access and server logs." },
            statusCode: StatusCodes.Status500InternalServerError);
    }
});

app.MapGet("/api/audit/events", async (HttpContext context, AuditStore audit) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    var limit = int.TryParse(context.Request.Query["limit"], out var requestedLimit) ? requestedLimit : 200;
    return Results.Ok(new { events = await audit.ListAsync(limit, context.RequestAborted) });
});

app.MapGet("/api/audit/verify", async (HttpContext context, AuditStore audit) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    return Results.Ok(new { verification = await audit.VerifyAsync(context.RequestAborted) });
});

app.MapPost("/api/auth/login", async (
    LoginRequest request,
    HttpContext context,
    AuthStore store,
    LoginRateLimiter limiter) =>
{
    if (!limiter.TryAcquire(context.Connection.RemoteIpAddress?.ToString() ?? "unknown", DateTimeOffset.UtcNow))
    {
        return Results.Json(new { error = "Too many sign-in attempts. Wait 15 minutes and try again." },
            statusCode: StatusCodes.Status429TooManyRequests);
    }

    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { error = "Email and password are required." });
    }

    var challengeResult = await store.CreateChallengeAsync(
        request.Email,
        request.Password,
        DateTimeOffset.UtcNow,
        context.RequestAborted);
    if (challengeResult is null)
    {
        limiter.RecordFailure(context.Connection.RemoteIpAddress?.ToString() ?? "unknown", DateTimeOffset.UtcNow);
        return Results.Json(new { error = "Invalid credentials or account unavailable." },
            statusCode: StatusCodes.Status401Unauthorized);
    }
    limiter.RecordSuccess(context.Connection.RemoteIpAddress?.ToString() ?? "unknown");

    return Results.Ok(new
    {
        challengeId = challengeResult.ChallengeId,
        state = challengeResult.NeedsMfaSetup ? "mfa_setup_required" : "mfa_required",
        secret = challengeResult.Secret,
        provisioningUri = challengeResult.ProvisioningUri,
        message = challengeResult.NeedsMfaSetup
            ? "Add this account to an authenticator app, then enter its six-digit code."
            : "Enter the current six-digit code from your authenticator app."
    });
});

app.MapPost("/api/auth/mfa/verify", async (
    MfaRequest request,
    HttpContext context,
    AuthStore store,
    AlertManagementStore alerts,
    LoginRateLimiter limiter) =>
{
    var key = "mfa:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
    if (!limiter.TryAcquire(key, DateTimeOffset.UtcNow))
    {
        return Results.Json(new { error = "Too many verification attempts. Wait 15 minutes and try again." },
            statusCode: StatusCodes.Status429TooManyRequests);
    }

    var result = await store.CompleteMfaAsync(
        request.ChallengeId,
        request.Code,
        request.DeviceId,
        request.DeviceName,
        request.DeviceSecret,
        request.WorkstationPolicy,
        setup: false,
        DateTimeOffset.UtcNow,
        context.RequestAborted);
    if (result.Result?.State == "device_pending")
    {
        await alerts.RecordUnregisteredDeviceAsync(
            result.Result.User?.UserId ?? "unknown",
            request.DeviceId,
            request.DeviceName,
            context.RequestAborted);
    }

    if (result.Error is not null)
    {
        limiter.RecordFailure(key, DateTimeOffset.UtcNow);
    }
    else
    {
        limiter.RecordSuccess(key);
    }

    return CompleteLoginResponse(context, result);
});

app.MapPost("/api/auth/mfa/setup", async (
    MfaSetupRequest request,
    HttpContext context,
    AuthStore store,
    AlertManagementStore alerts,
    LoginRateLimiter limiter) =>
{
    var key = "mfa:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
    if (!limiter.TryAcquire(key, DateTimeOffset.UtcNow))
    {
        return Results.Json(new { error = "Too many verification attempts. Wait 15 minutes and try again." },
            statusCode: StatusCodes.Status429TooManyRequests);
    }

    var result = await store.CompleteMfaAsync(
        request.ChallengeId,
        request.Code,
        request.DeviceId,
        request.DeviceName,
        request.DeviceSecret,
        request.WorkstationPolicy,
        setup: true,
        DateTimeOffset.UtcNow,
        context.RequestAborted);
    if (result.Result?.State == "device_pending")
    {
        await alerts.RecordUnregisteredDeviceAsync(
            result.Result.User?.UserId ?? "unknown",
            request.DeviceId,
            request.DeviceName,
            context.RequestAborted);
    }

    if (result.Error is not null)
    {
        limiter.RecordFailure(key, DateTimeOffset.UtcNow);
    }
    else
    {
        limiter.RecordSuccess(key);
    }

    return CompleteLoginResponse(context, result);
});

app.MapGet("/api/auth/me", (HttpContext context) =>
{
    var session = GetSession(context);
    return Results.Ok(new
    {
        user = new
        {
            userId = session.UserId,
            displayName = session.DisplayName,
            email = session.Email,
            role = session.Role,
            mfaEnabled = session.MfaEnabled
        },
        deviceId = session.DeviceId,
        expiresAt = session.ExpiresAt
    });
});

app.MapPost("/api/auth/logout", async (HttpContext context, AuthStore store) =>
{
    var session = GetSession(context);
    await store.RevokeSessionAsync(session.SessionId, context.RequestAborted);
    context.Response.Cookies.Delete("secureExamSession", CookieOptions(context.Request.IsHttps));
    return Results.Ok(new { message = "Signed out." });
});

app.MapPost("/api/auth/change-password", async (
    ChangePasswordRequest request,
    HttpContext context,
    AuthStore store) =>
{
    try
    {
        await store.ChangePasswordAsync(
            GetSession(context).UserId,
            request.CurrentPassword,
            request.NewPassword,
            context.RequestAborted);
        context.Response.Cookies.Delete("secureExamSession", CookieOptions(context.Request.IsHttps));
        return Results.Ok(new { message = "Password changed. Sign in again with your new password." });
    }
    catch (UnauthorizedAccessException exception)
    {
        return Results.Json(new { error = exception.Message }, statusCode: StatusCodes.Status401Unauthorized);
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapGet("/api/auth/users", async (HttpContext context, AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    return Results.Ok(new { users = await store.ListUsersAsync(context.RequestAborted) });
});

app.MapPost("/api/auth/users", async (CreateUserRequest request, HttpContext context, AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var created = await store.CreateUserAsync(request, context.RequestAborted);
        return Results.Created($"/api/auth/users/{created.UserId}", new { user = created });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
    catch (Microsoft.Data.Sqlite.SqliteException)
    {
        return Results.Conflict(new { error = "That email address is already registered." });
    }
});

app.MapMethods("/api/auth/users/{userId}/status", new[] { "PATCH" }, async (
    string userId,
    DeviceStatusRequest request,
    HttpContext context,
    AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var user = await store.SetUserStatusAsync(
            userId,
            request.Status,
            context.RequestAborted);
        return user is null ? Results.NotFound(new { error = "User not found." }) : Results.Ok(new { user });
    }
    catch (InvalidOperationException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapMethods("/api/auth/users/{userId}/role", new[] { "PATCH" }, async (
    string userId,
    RoleRequest request,
    HttpContext context,
    AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var user = await store.SetUserRoleAsync(
            userId,
            request.Role,
            GetSession(context).UserId,
            context.RequestAborted);
        return user is null ? Results.NotFound(new { error = "User not found." }) : Results.Ok(new { user });
    }
    catch (InvalidOperationException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapPost("/api/auth/users/{userId}/reset-mfa", async (
    string userId,
    HttpContext context,
    AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    var reset = await store.ResetMfaAsync(userId, context.RequestAborted);
    return reset
        ? Results.Ok(new { userId, message = "MFA reset. The user must enroll again." })
        : Results.NotFound(new { error = "User not found." });
});

app.MapGet("/api/auth/devices", async (HttpContext context, AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    return Results.Ok(new { devices = await store.ListDevicesAsync(context.RequestAborted) });
});

app.MapMethods("/api/auth/devices/{deviceId}/status", new[] { "PATCH" }, async (
    string deviceId,
    DeviceStatusRequest request,
    HttpContext context,
    AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    if (request.Status is not ("approved" or "revoked"))
    {
        return Results.BadRequest(new { error = "Status must be approved or revoked." });
    }

    var changed = await store.SetDeviceStatusAsync(deviceId, request.Status, context.RequestAborted);
    return changed
        ? Results.Ok(new { deviceId, status = request.Status })
        : Results.NotFound(new { error = "Device not found." });
});

app.MapMethods("/api/auth/devices/{deviceId}/workstation", new[] { "PUT" }, async (
    string deviceId,
    WorkstationAssignmentRequest request,
    HttpContext context,
    AuthStore store) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var changed = await store.AssignWorkstationAsync(
            deviceId, request.Centre, request.Room, request.WorkstationId, context.RequestAborted);
        return changed
            ? Results.Ok(new { deviceId, request.Centre, request.Room, request.WorkstationId })
            : Results.NotFound(new { error = "Workstation not found." });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapGet("/api/papers", async (HttpContext context, PaperStore papers) =>
{
    var session = GetSession(context);
    return Results.Ok(new { papers = await papers.ListAsync(session.UserId, session.Role, context.RequestAborted) });
});

app.MapGet("/api/papers/distribution-grants", async (HttpContext context, PaperStore papers) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    return Results.Ok(new { grants = await papers.ListDistributionGrantsAsync(context.RequestAborted) });
});

app.MapPost("/api/papers/distribution-grants", async (
    CreateDistributionGrantRequest request,
    HttpContext context,
    PaperStore papers) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var grant = await papers.CreateDistributionGrantAsync(
            request.PaperId,
            request.RecipientUserId,
            GetSession(context).UserId,
            request.ExpiresAt,
            DateTimeOffset.UtcNow,
            context.RequestAborted);
        return grant is null
            ? Results.NotFound(new { error = "Approved paper or active recipient account was not found." })
            : Results.Created($"/api/papers/distribution-grants/{grant.GrantId}", new { grant });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapMethods("/api/papers/distribution-grants/{grantId}/revoke", new[] { "PATCH" }, async (
    string grantId,
    HttpContext context,
    PaperStore papers) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    var revoked = await papers.RevokeDistributionGrantAsync(
        grantId, DateTimeOffset.UtcNow, context.RequestAborted);
    return revoked
        ? Results.Ok(new { grantId, revoked = true })
        : Results.NotFound(new { error = "Active distribution grant not found." });
});

app.MapGet("/api/papers/issued-copies", async (HttpContext context, PaperStore papers) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    var limit = int.TryParse(context.Request.Query["limit"], out var requestedLimit) ? requestedLimit : 200;
    return Results.Ok(new { copies = await papers.ListIssuedCopiesAsync(limit, context.RequestAborted) });
});

app.MapPost("/api/papers", async (
    PaperDraftRequest request,
    HttpContext context,
    PaperStore papers) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "setter"))
    {
        return Results.Json(new { error = "Only paper setters and administrators can create drafts." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var paper = await papers.SaveDraftAsync(
            null, session.UserId, session.Role, request, DateTimeOffset.UtcNow, context.RequestAborted);
        return Results.Created($"/api/papers/{paper.PaperId}", new { paper });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapGet("/api/papers/{paperId}", async (
    string paperId,
    HttpContext context,
    PaperStore papers) =>
{
    var session = GetSession(context);
    var access = await papers.GetForViewAsync(
        paperId, session.UserId, session.Role, DateTimeOffset.UtcNow, context.RequestAborted);
    return access.Paper is null
        ? Results.NotFound(new { error = "Paper not found or no active distribution grant exists." })
        : Results.Ok(new { paper = access.Paper, issuedCopyId = access.CopyId });
});

app.MapPut("/api/papers/{paperId}", async (
    string paperId,
    PaperDraftRequest request,
    HttpContext context,
    PaperStore papers) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "setter"))
    {
        return Results.Json(new { error = "Only paper setters and administrators can edit drafts." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var paper = await papers.SaveDraftAsync(
            paperId, session.UserId, session.Role, request, DateTimeOffset.UtcNow, context.RequestAborted);
        return Results.Ok(new { paper });
    }
    catch (KeyNotFoundException)
    {
        return Results.NotFound(new { error = "Paper not found or not accessible." });
    }
    catch (UnauthorizedAccessException exception)
    {
        return Results.Json(new { error = exception.Message }, statusCode: StatusCodes.Status403Forbidden);
    }
    catch (InvalidOperationException exception)
    {
        return Results.Conflict(new { error = exception.Message });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapGet("/api/papers/{paperId}/versions", async (
    string paperId,
    HttpContext context,
    PaperStore papers) =>
{
    var session = GetSession(context);
    var versions = await papers.GetVersionsAsync(paperId, session.UserId, session.Role, context.RequestAborted);
    return versions is null
        ? Results.NotFound(new { error = "Paper not found." })
        : Results.Ok(new { versions });
});

app.MapPost("/api/papers/{paperId}/transition", async (
    string paperId,
    PaperTransitionRequest request,
    HttpContext context,
    PaperStore papers) =>
{
    var session = GetSession(context);
    try
    {
        var paper = await papers.TransitionAsync(
            paperId, session.UserId, session.Role, request.Action, request.Comment,
            DateTimeOffset.UtcNow, context.RequestAborted);
        return paper is null
            ? Results.NotFound(new { error = "Paper not found or not accessible." })
            : Results.Ok(new { paper });
    }
    catch (UnauthorizedAccessException exception)
    {
        return Results.Json(new { error = exception.Message }, statusCode: StatusCodes.Status403Forbidden);
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
    catch (InvalidOperationException exception)
    {
        return Results.Conflict(new { error = exception.Message });
    }
});

app.MapPost("/api/papers/{paperId}/export", async (
    string paperId,
    HttpContext context,
    PaperStore papers) =>
{
    var session = GetSession(context);
    try
    {
        var access = await papers.GetApprovedForAccessAsync(
            paperId, session.UserId, session.Role, "export", DateTimeOffset.UtcNow, context.RequestAborted);
        return access.Paper is null
            ? Results.NotFound(new { error = "Only an approved paper with an active recipient grant can be exported." })
            : Results.Ok(new { paper = access.Paper, integritySha256 = access.ContentSha256, issuedCopyId = access.CopyId });
    }
    catch (PaperIntegrityException exception)
    {
        app.Logger.LogError(exception, "Paper integrity verification failed during export for paper {PaperId}.", paperId);
        return Results.Conflict(new { error = exception.Message });
    }
});

app.MapPost("/api/papers/{paperId}/print", async (
    string paperId,
    HttpContext context,
    PaperStore papers) =>
{
    var session = GetSession(context);
    try
    {
        var access = await papers.GetApprovedForAccessAsync(
            paperId, session.UserId, session.Role, "print", DateTimeOffset.UtcNow, context.RequestAborted);
        return access.Paper is null
            ? Results.NotFound(new { error = "Only an approved paper with an active recipient grant can be printed." })
            : Results.Ok(new { paper = access.Paper, integritySha256 = access.ContentSha256, issuedCopyId = access.CopyId });
    }
    catch (PaperIntegrityException exception)
    {
        app.Logger.LogError(exception, "Paper integrity verification failed during print for paper {PaperId}.", paperId);
        return Results.Conflict(new { error = exception.Message });
    }
});

app.MapPost("/api/papers/{paperId}/watermarked-copy", async (
    string paperId,
    HttpContext context,
    PaperStore papers,
    DocumentFingerprintStore fingerprints,
    WatermarkedPdfService pdfService) =>
{
    var session = GetSession(context);
    var issuedAt = DateTimeOffset.UtcNow;
    try
    {
        var access = await papers.GetApprovedForAccessAsync(
            paperId, session.UserId, session.Role, "export", issuedAt, context.RequestAborted);
        if (access.Paper is null || access.CopyId is null || access.ContentSha256 is null)
        {
            return Results.NotFound(new { error = "Only an approved paper with an active recipient grant can be exported." });
        }

        var pdf = pdfService.Create(access.Paper, access.CopyId, session.DisplayName, session.Email);
        var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(pdf));
        await fingerprints.RecordAsync(
            access.CopyId,
            access.Paper,
            session.UserId,
            session.DisplayName,
            session.Email,
            access.ContentSha256,
            fingerprint,
            issuedAt,
            context.RequestAborted);
        context.Response.Headers["Cache-Control"] = "no-store";
        context.Response.Headers["X-SecureExam-CopyId"] = access.CopyId;
        context.Response.Headers["X-SecureExam-Pdf-Sha256"] = fingerprint;
        return Results.File(pdf, "application/pdf", $"paper-copy-{access.CopyId}.pdf");
    }
    catch (PaperIntegrityException exception)
    {
        app.Logger.LogError(exception, "Paper integrity verification failed during PDF issuance for paper {PaperId}.", paperId);
        return Results.Conflict(new { error = exception.Message });
    }
});

app.MapPost("/api/document-tracing/verify", async (
    HttpContext context,
    DocumentFingerprintStore fingerprints) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "investigator"))
    {
        return Results.Json(new { error = "Only administrators and investigators can verify recovered copies." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    const long maxUploadBytes = 25 * 1024 * 1024;
    var requestLimit = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (requestLimit is { IsReadOnly: false })
    {
        requestLimit.MaxRequestBodySize = maxUploadBytes + 1024 * 1024;
    }

    if (context.Request.ContentLength is > maxUploadBytes + 1024 * 1024)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }

    if (!context.Request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "Upload a PDF using the 'document' form field." });
    }

    var form = await context.Request.ReadFormAsync(context.RequestAborted);
    var file = form.Files.GetFile("document");
    if (file is null || file.Length == 0 || file.Length > maxUploadBytes)
    {
        return Results.BadRequest(new { error = "Select a non-empty PDF no larger than 25 MB." });
    }

    await using var stream = file.OpenReadStream();
    using var buffer = new MemoryStream((int)file.Length);
    await stream.CopyToAsync(buffer, context.RequestAborted);
    var pdf = buffer.ToArray();
    if (pdf.Length < 5 ||
        pdf[0] != (byte)'%' || pdf[1] != (byte)'P' || pdf[2] != (byte)'D' || pdf[3] != (byte)'F' || pdf[4] != (byte)'-')
    {
        return Results.BadRequest(new { error = "The uploaded file is not a valid PDF document." });
    }

    var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(pdf));
    var match = await fingerprints.FindAsync(fingerprint, context.RequestAborted)
        ?? new DocumentFingerprintMatch(false, null, null, null, null, null, null, null, null, fingerprint);
    return Results.Ok(new { match });
});

app.MapGet("/api/investigations/search", async (
    string type,
    string query,
    HttpContext context,
    InvestigationService investigations) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "investigator"))
    {
        return Results.Json(new { error = "Only administrators and investigators can search investigation evidence." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var report = await investigations.SearchAsync(type, query, context.RequestAborted);
        return Results.Ok(new { report });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapPost("/api/investigations/incidents", async (
    CreateInvestigationIncidentRequest request,
    HttpContext context,
    InvestigationStore investigations) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "investigator"))
    {
        return Results.Json(new { error = "Only administrators and investigators can register investigation incidents." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var incident = await investigations.CreateIncidentAsync(
            request, session.UserId, session.DisplayName, DateTimeOffset.UtcNow, context.RequestAborted);
        return Results.Created($"/api/investigations/search?type=incident&query={Uri.EscapeDataString(incident.IncidentId)}",
            new { incident });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
});

app.MapGet("/api/alerts", async (HttpContext context, AlertManagementStore alerts) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "investigator"))
    {
        return Results.Json(new { error = "Only administrators and investigators can view security alerts." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    var status = context.Request.Query["status"].FirstOrDefault();
    if (status is not null && status is not ("open" or "reviewed" or "resolved"))
    {
        return Results.BadRequest(new { error = "Alert status must be open, reviewed, or resolved." });
    }

    return Results.Ok(new
    {
        alerts = await alerts.ListAsync(500, status, context.RequestAborted),
        cases = await alerts.ListCasesAsync(context.RequestAborted)
    });
});

app.MapPost("/api/alerts/{alertId}/review", async (
    string alertId,
    AlertActionRequest request,
    HttpContext context,
    AlertManagementStore alerts) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "investigator"))
    {
        return Results.Json(new { error = "Only administrators and investigators can review alerts." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var alert = await alerts.AddActionAsync(
            alertId, "reviewed", session.UserId, session.DisplayName, request.Note,
            DateTimeOffset.UtcNow, context.RequestAborted);
        return alert is null ? Results.NotFound(new { error = "Alert not found." }) : Results.Ok(new { alert });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
    catch (InvalidOperationException exception)
    {
        return Results.Conflict(new { error = exception.Message });
    }
});

app.MapPost("/api/alerts/{alertId}/resolve", async (
    string alertId,
    AlertActionRequest request,
    HttpContext context,
    AlertManagementStore alerts) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "investigator"))
    {
        return Results.Json(new { error = "Only administrators and investigators can resolve alerts." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var alert = await alerts.AddActionAsync(
            alertId, "resolved", session.UserId, session.DisplayName, request.Note,
            DateTimeOffset.UtcNow, context.RequestAborted);
        return alert is null ? Results.NotFound(new { error = "Alert not found." }) : Results.Ok(new { alert });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
    catch (InvalidOperationException exception)
    {
        return Results.Conflict(new { error = exception.Message });
    }
});

app.MapPost("/api/alerts/{alertId}/cases", async (
    string alertId,
    CreateAlertCaseRequest request,
    HttpContext context,
    AlertManagementStore alerts) =>
{
    var session = GetSession(context);
    if (session.Role is not ("admin" or "investigator"))
    {
        return Results.Json(new { error = "Only administrators and investigators can create incident cases." },
            statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var incidentCase = await alerts.CreateCaseAsync(
            alertId, request, session.UserId, session.DisplayName, DateTimeOffset.UtcNow, context.RequestAborted);
        return incidentCase is null
            ? Results.NotFound(new { error = "Alert not found." })
            : Results.Created($"/api/alerts?status=open", new { incidentCase });
    }
    catch (ArgumentException exception)
    {
        return Results.BadRequest(new { error = exception.Message });
    }
    catch (InvalidOperationException exception)
    {
        return Results.Conflict(new { error = exception.Message });
    }
});

app.MapGet("/api/papers/access-events", async (HttpContext context, PaperStore papers) =>
{
    if (!IsAdmin(context))
    {
        return Results.Json(new { error = "Insufficient permissions." }, statusCode: StatusCodes.Status403Forbidden);
    }

    return Results.Ok(new { events = await papers.ListAccessEventsAsync(context.RequestAborted) });
});

app.Run();

static async Task<AuditClassification> ClassifyAuditEventAsync(HttpContext context)
{
    var path = context.Request.Path.Value ?? string.Empty;
    var workstationId = await ReadJsonStringAsync(context, "deviceId");
    if (path == "/api/auth/login" || path.StartsWith("/api/auth/mfa/", StringComparison.Ordinal))
    {
        return new AuditClassification("login", null, null, workstationId,
            path == "/api/auth/login" ? " · password challenge" : " · MFA verification");
    }

    if (path == "/api/auth/logout")
    {
        return new AuditClassification("logout", "session", null, null, string.Empty);
    }

    if (path.StartsWith("/api/papers", StringComparison.Ordinal))
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var resourceId = segments.Length > 2 && segments[2] is not ("access-events")
            ? segments[2]
            : null;
        var resourceType = resourceId is null ? "paper_collection" : "paper";
        if (path.EndsWith("/export", StringComparison.Ordinal) ||
            path.EndsWith("/watermarked-copy", StringComparison.Ordinal))
        {
            return new AuditClassification("export", resourceType, resourceId, null, string.Empty);
        }

        if (path.EndsWith("/print", StringComparison.Ordinal))
        {
            return new AuditClassification("print", resourceType, resourceId, null, string.Empty);
        }

        if (path.EndsWith("/transition", StringComparison.Ordinal))
        {
            var action = await ReadJsonStringAsync(context, "action");
            var eventType = action switch
            {
                "submit" => "submission",
                "approve" => "approval",
                "request_changes" => "change_request",
                "reject" => "rejection",
                _ => "paper_transition"
            };
            return new AuditClassification(eventType, resourceType, resourceId, null,
                action is null ? string.Empty : $" · action={action}");
        }

        return context.Request.Method == HttpMethods.Get
            ? new AuditClassification("view", resourceType, resourceId, null, string.Empty)
            : new AuditClassification("edit", resourceType, resourceId, null, string.Empty);
    }

    if (path == "/api/audit/verify")
    {
        return new AuditClassification("audit_verification", "audit_chain", null, null, string.Empty);
    }

    if (path.StartsWith("/api/investigations", StringComparison.Ordinal))
    {
        return path.EndsWith("/incidents", StringComparison.Ordinal)
            ? new AuditClassification("investigation_incident_created", "incident", null, null, string.Empty)
            : new AuditClassification("investigation_search", "investigation", null, null, string.Empty);
    }

    if (path.StartsWith("/api/alerts", StringComparison.Ordinal))
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var alertId = segments.Length > 2 ? segments[2] : null;
        var action = segments.Length > 3 ? segments[3] : null;
        var eventType = action switch
        {
            "review" => "alert_reviewed",
            "resolve" => "alert_resolved",
            "cases" => "alert_case_created",
            _ => "alert_access"
        };
        return new AuditClassification(eventType, "security_alert", alertId, null,
            action is null ? string.Empty : $" · action={action}");
    }

    return context.Request.Method == HttpMethods.Get
        ? new AuditClassification("view", "api_resource", path, null, string.Empty)
        : new AuditClassification("edit", "api_resource", path, null, string.Empty);
}

static async Task<string?> ReadJsonStringAsync(HttpContext context, string propertyName)
{
    if (!context.Request.HasJsonContentType() || context.Request.ContentLength == 0)
    {
        return null;
    }

    context.Request.EnableBuffering();
    context.Request.Body.Position = 0;
    try
    {
        using var document = await JsonDocument.ParseAsync(
            context.Request.Body,
            new JsonDocumentOptions { MaxDepth = 8 },
            context.RequestAborted);
        return document.RootElement.ValueKind == JsonValueKind.Object &&
               document.RootElement.TryGetProperty(propertyName, out var value) &&
               value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }
    catch (JsonException)
    {
        return null;
    }
    finally
    {
        context.Request.Body.Position = 0;
    }
}

static IResult CompleteLoginResponse(
    HttpContext context,
    (LoginResult? Result, string? SessionToken, string? Error) result)
{
    if (result.Error is not null)
    {
        return Results.Json(new { error = result.Error }, statusCode: StatusCodes.Status401Unauthorized);
    }

    if (result.Result is null)
    {
        return Results.Json(new { error = "Sign-in could not be completed." },
            statusCode: StatusCodes.Status400BadRequest);
    }

    if (result.SessionToken is not null)
    {
        context.Response.Cookies.Append(
            "secureExamSession",
            result.SessionToken,
            CookieOptions(context.Request.IsHttps, result.Result.ExpiresAt));
    }

    return Results.Ok(new
    {
        state = result.Result.State,
        user = result.Result.User,
        expiresAt = result.Result.ExpiresAt,
        message = result.Result.Message
    });
}

static CookieOptions CookieOptions(bool secure, DateTimeOffset? expiresAt = null) => new()
{
    HttpOnly = true,
    Secure = secure,
    SameSite = SameSiteMode.Strict,
    Path = "/",
    Expires = expiresAt
};

static bool IsPublicEndpoint(PathString path) =>
    path == "/health" ||
    path == "/api/auth/login" ||
    path == "/api/auth/mfa/setup" ||
    path == "/api/auth/mfa/verify";

static SessionIdentity GetSession(HttpContext context) =>
    context.Items["SecureExam.Session"] as SessionIdentity
    ?? throw new InvalidOperationException("Authenticated session context is unavailable.");

static bool IsAdmin(HttpContext context) =>
    context.Items["SecureExam.Session"] is SessionIdentity session && session.Role == "admin";

internal sealed class LoginRateLimiter
{
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _attempts = new();
    private const int MaxAttempts = 8;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    public bool TryAcquire(string key, DateTimeOffset now)
    {
        var queue = _attempts.GetOrAdd(key, _ => new Queue<DateTimeOffset>());
        lock (queue)
        {
            Prune(queue, now);
            if (queue.Count >= MaxAttempts)
            {
                return false;
            }

            return true;
        }
    }

    public void RecordFailure(string key, DateTimeOffset now)
    {
        var queue = _attempts.GetOrAdd(key, _ => new Queue<DateTimeOffset>());
        lock (queue)
        {
            Prune(queue, now);
            queue.Enqueue(now);
        }
    }

    public void RecordSuccess(string key)
    {
        _attempts.TryRemove(key, out _);
    }

    private static void Prune(Queue<DateTimeOffset> queue, DateTimeOffset now)
    {
        while (queue.Count > 0 && now - queue.Peek() >= Window)
        {
            queue.Dequeue();
        }
    }
}
