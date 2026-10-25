using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using SecureExam.Api.Models;
using SecureExam.Api.Security;

namespace SecureExam.Api.Data;

internal sealed class AuthStore
{
    private static readonly string DummyPasswordHash = PasswordHasher.Hash(
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    private readonly string _connectionString;
    private readonly IDataProtector _secretProtector;
    private readonly bool _requireCompliantWorkstations;
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private bool _initialized;

    public AuthStore(IConfiguration configuration, IDataProtectionProvider protectionProvider)
    {
        _requireCompliantWorkstations =
            bool.TryParse(configuration["SECURE_EXAM_REQUIRE_COMPLIANT_WORKSTATION"], out var requireCompliance) &&
            requireCompliance;
        var dataDirectory = configuration["SECURE_EXAM_DATA_DIR"];
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            dataDirectory = Path.Combine(AppContext.BaseDirectory, "data");
        }

        Directory.CreateDirectory(dataDirectory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(dataDirectory, "secure-exam-auth.db"),
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();
        _secretProtector = protectionProvider.CreateProtector("SecureExam.Auth.Totp.v1");
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized)
        {
            return;
        }

        await _initializeLock.WaitAsync(cancellationToken);
        try
        {
            if (_initialized)
            {
                return;
            }

            await using var connection = await OpenAsync(cancellationToken);
            var command = connection.CreateCommand();
            command.CommandText =
                "PRAGMA journal_mode=WAL;" +
                "CREATE TABLE IF NOT EXISTS users (" +
                "user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE, " +
                "role TEXT NOT NULL CHECK(role IN ('admin','setter','reviewer','investigator')), " +
                "status TEXT NOT NULL CHECK(status IN ('active','disabled')), password_hash TEXT NOT NULL, " +
                "mfa_secret TEXT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT NULL, " +
                "created_at TEXT NOT NULL, last_login_at TEXT NULL);" +
                "CREATE TABLE IF NOT EXISTS login_challenges (" +
                "challenge_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, setup_secret TEXT NULL, " +
                "expires_at TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0);" +
                "CREATE TABLE IF NOT EXISTS devices (" +
                "device_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, secret_hash TEXT NOT NULL, " +
                "status TEXT NOT NULL CHECK(status IN ('pending','approved','revoked')), created_at TEXT NOT NULL, " +
                "last_seen_at TEXT NULL, centre TEXT NOT NULL DEFAULT 'Unassigned', room TEXT NOT NULL DEFAULT 'Unassigned', " +
                "workstation_id TEXT NOT NULL DEFAULT 'Unassigned', compliance_status TEXT NOT NULL DEFAULT 'unknown', " +
                "operating_system TEXT NOT NULL DEFAULT '', application_control_detected INTEGER NOT NULL DEFAULT 0, " +
                "system_restrictions_configured INTEGER NOT NULL DEFAULT 0, compliance_checked_at TEXT NULL);" +
                "CREATE TABLE IF NOT EXISTS sessions (" +
                "session_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL, " +
                "created_at TEXT NOT NULL, expires_at TEXT NOT NULL);" +
                "CREATE TABLE IF NOT EXISTS totp_steps (user_id TEXT PRIMARY KEY, last_step INTEGER NOT NULL);" +
                "CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON login_challenges(expires_at);" +
                "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);" +
                "CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);";
            await command.ExecuteNonQueryAsync(cancellationToken);
            await EnsureDeviceColumnAsync(connection, "centre", "TEXT NOT NULL DEFAULT 'Unassigned'", cancellationToken);
            await EnsureDeviceColumnAsync(connection, "room", "TEXT NOT NULL DEFAULT 'Unassigned'", cancellationToken);
            await EnsureDeviceColumnAsync(connection, "workstation_id", "TEXT NOT NULL DEFAULT 'Unassigned'", cancellationToken);
            await EnsureDeviceColumnAsync(connection, "compliance_status", "TEXT NOT NULL DEFAULT 'unknown'", cancellationToken);
            await EnsureDeviceColumnAsync(connection, "operating_system", "TEXT NOT NULL DEFAULT ''", cancellationToken);
            var hasApplicationControlColumn =
                await DeviceColumnExistsAsync(connection, "application_control_detected", cancellationToken);
            var hasLegacyApplicationControlColumn =
                await DeviceColumnExistsAsync(connection, "app_control_enforced", cancellationToken);
            if (!hasApplicationControlColumn)
            {
                await EnsureDeviceColumnAsync(
                    connection, "application_control_detected", "INTEGER NOT NULL DEFAULT 0", cancellationToken);
                if (hasLegacyApplicationControlColumn)
                {
                    var migratePolicy = connection.CreateCommand();
                    migratePolicy.CommandText =
                        "UPDATE devices SET application_control_detected=app_control_enforced;";
                    await migratePolicy.ExecuteNonQueryAsync(cancellationToken);
                }
            }
            await EnsureDeviceColumnAsync(connection, "system_restrictions_configured", "INTEGER NOT NULL DEFAULT 0", cancellationToken);
            await EnsureDeviceColumnAsync(connection, "compliance_checked_at", "TEXT NULL", cancellationToken);
            _initialized = true;
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    public async Task BootstrapAdministratorAsync(string email, string password, string displayName, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var countCommand = connection.CreateCommand();
        countCommand.CommandText = "SELECT COUNT(*) FROM users;";
        var count = (long)(await countCommand.ExecuteScalarAsync(cancellationToken) ?? 0L);
        if (count > 0)
        {
            return;
        }

        ValidatePassword(password);
        await InsertUserAsync(connection, email, displayName, "admin", password, cancellationToken);
    }

    public async Task<bool> HasUsersAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT EXISTS(SELECT 1 FROM users LIMIT 1);";
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken)) == 1;
    }

    public async Task<LoginChallenge?> CreateChallengeAsync(string email, string password, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var cleanup = connection.CreateCommand();
        cleanup.CommandText = "DELETE FROM login_challenges WHERE expires_at <= $now; DELETE FROM sessions WHERE expires_at <= $now;";
        cleanup.Parameters.AddWithValue("$now", now.ToString("O"));
        await cleanup.ExecuteNonQueryAsync(cancellationToken);
        var user = await GetUserByEmailAsync(connection, email, cancellationToken);
        if (user is null)
        {
            PasswordHasher.Verify(password, DummyPasswordHash);
            return null;
        }

        if (user.Status != "active" || (user.LockedUntil is not null && user.LockedUntil > now))
        {
            PasswordHasher.Verify(password, user.PasswordHash);
            await RecordFailedLoginAsync(connection, user.UserId, now, cancellationToken);
            return null;
        }

        if (!PasswordHasher.Verify(password, user.PasswordHash))
        {
            await RecordFailedLoginAsync(connection, user.UserId, now, cancellationToken);
            return null;
        }

        var setupSecret = user.MfaSecret is null ? _secretProtector.Protect(Totp.NewSecret()) : null;
        var challenge = NewToken();
        var insert = connection.CreateCommand();
        insert.CommandText =
            "INSERT INTO login_challenges(challenge_hash,user_id,setup_secret,expires_at,failed_attempts) " +
            "VALUES($hash,$user,$secret,$expires,0);";
        insert.Parameters.AddWithValue("$hash", HashToken(challenge));
        insert.Parameters.AddWithValue("$user", user.UserId);
        insert.Parameters.AddWithValue("$secret", (object?)setupSecret ?? DBNull.Value);
        insert.Parameters.AddWithValue("$expires", now.AddMinutes(5).ToString("O"));
        await insert.ExecuteNonQueryAsync(cancellationToken);

        var secret = setupSecret is null ? null : _secretProtector.Unprotect(setupSecret);
        var provisioningUri = secret is null
            ? null
            : $"otpauth://totp/SecureExam:{Uri.EscapeDataString(user.Email)}?secret={Totp.ToBase32(secret)}&issuer=SecureExam&digits=6&period=30";
        return new LoginChallenge(
            challenge,
            setupSecret is not null,
            secret is null ? null : Totp.ToBase32(secret),
            provisioningUri);
    }

    public async Task<(LoginResult? Result, string? SessionToken, string? Error)> CompleteMfaAsync(
        string challengeId,
        string code,
        string deviceId,
        string deviceName,
        string deviceSecret,
        WorkstationPolicyReport workstationPolicy,
        bool setup,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!IsValidDeviceInput(deviceId, deviceName, deviceSecret))
        {
            return (null, null, "Invalid device registration details.");
        }

        if (!IsValidWorkstationPolicy(workstationPolicy))
        {
            return (null, null, "Invalid workstation policy report.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        var challenge = await GetChallengeAsync(connection, challengeId, now, cancellationToken);
        if (challenge is null || (challenge.SetupSecret is not null) != setup)
        {
            return (null, null, "The sign-in challenge expired or is invalid. Sign in again.");
        }

        var user = await GetUserByIdAsync(connection, challenge.UserId, cancellationToken);
        if (user is null || user.Status != "active")
        {
            await DeleteChallengeAsync(connection, challengeId, cancellationToken);
            return (null, null, "Account is unavailable.");
        }

        var secret = setup
            ? _secretProtector.Unprotect(challenge.SetupSecret!)
            : user.MfaSecret is null ? null : _secretProtector.Unprotect(user.MfaSecret);
        if (secret is null || !Totp.TryVerify(secret, code, now, out var matchedStep))
        {
            await IncrementChallengeFailureAsync(connection, challengeId, challenge.FailedAttempts, cancellationToken);
            return (null, null, "The verification code is invalid. Check your authenticator and try again.");
        }

        var consumeCode = connection.CreateCommand();
        consumeCode.CommandText =
            "INSERT INTO totp_steps(user_id,last_step) VALUES($user,$step) " +
            "ON CONFLICT(user_id) DO UPDATE SET last_step=excluded.last_step " +
            "WHERE excluded.last_step > totp_steps.last_step;";
        consumeCode.Parameters.AddWithValue("$user", user.UserId);
        consumeCode.Parameters.AddWithValue("$step", matchedStep);
        if (await consumeCode.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            await IncrementChallengeFailureAsync(connection, challengeId, challenge.FailedAttempts, cancellationToken);
            return (null, null, "That authenticator code was already used. Wait for the next code.");
        }

        if (setup)
        {
            var updateMfa = connection.CreateCommand();
            updateMfa.CommandText = "UPDATE users SET mfa_secret=$secret WHERE user_id=$user;";
            updateMfa.Parameters.AddWithValue("$secret", challenge.SetupSecret!);
            updateMfa.Parameters.AddWithValue("$user", user.UserId);
            await updateMfa.ExecuteNonQueryAsync(cancellationToken);
        }

        await DeleteChallengeAsync(connection, challengeId, cancellationToken);

        var device = await GetDeviceAsync(connection, deviceId, cancellationToken);
        if (device is not null && device.UserId != user.UserId)
        {
            return (null, null, "This device is registered to another account.");
        }

        if (device is null)
        {
            var approvedCountCommand = connection.CreateCommand();
            approvedCountCommand.CommandText = "SELECT COUNT(*) FROM devices WHERE status='approved';";
            var approvedCount = (long)(await approvedCountCommand.ExecuteScalarAsync(cancellationToken) ?? 0L);
            var isFirstDeviceForBootstrapAdmin =
                user.Role == "admin" &&
                approvedCount == 0 &&
                string.Equals(user.Email, Environment.GetEnvironmentVariable("SECURE_EXAM_ADMIN_EMAIL"), StringComparison.OrdinalIgnoreCase);
            var status = isFirstDeviceForBootstrapAdmin ? "approved" : "pending";
            var insertDevice = connection.CreateCommand();
            insertDevice.CommandText =
                "INSERT INTO devices(device_id,user_id,name,secret_hash,status,created_at,operating_system," +
                "application_control_detected,system_restrictions_configured,compliance_status,compliance_checked_at) " +
                "VALUES($id,$user,$name,$secret,$status,$created,$os,$appControl,$systemRestrictions,$compliance,$checked);";
            insertDevice.Parameters.AddWithValue("$id", deviceId);
            insertDevice.Parameters.AddWithValue("$user", user.UserId);
            insertDevice.Parameters.AddWithValue("$name", deviceName.Trim());
            insertDevice.Parameters.AddWithValue("$secret", HashToken(deviceSecret));
            insertDevice.Parameters.AddWithValue("$status", status);
            insertDevice.Parameters.AddWithValue("$created", now.ToString("O"));
            AddPolicyParameters(insertDevice, workstationPolicy, now);
            await insertDevice.ExecuteNonQueryAsync(cancellationToken);

            if (status == "pending")
            {
                return (new LoginResult("device_pending", ToSummary(user), null,
                    "This device is registered and awaiting administrator approval. Sign in again after approval."),
                    null,
                    null);
            }
        }
        else
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(device.SecretHash),
                    Encoding.ASCII.GetBytes(HashToken(deviceSecret))))
            {
                return (null, null, "Device verification failed. Re-enroll this device with an administrator.");
            }

            await SaveWorkstationPolicyAsync(connection, deviceId, workstationPolicy, now, cancellationToken);
            if (device.Status != "approved")
            {
                return (new LoginResult("device_pending", ToSummary(user), null,
                    device.Status == "revoked"
                        ? "This device has been revoked. Contact an administrator."
                        : "This device is awaiting administrator approval."),
                    null,
                    null);
            }

        }

        if (_requireCompliantWorkstations && !IsCompliant(workstationPolicy))
        {
            return (new LoginResult(
                    "workstation_noncompliant",
                    ToSummary(user),
                    null,
                    "This workstation does not meet the configured Windows policy requirements. Contact your administrator."),
                null,
                null);
        }

        var nowText = now.ToString("O");
        var sessionExpires = now.AddHours(8);
        var sessionToken = NewToken();
        var insertSession = connection.CreateCommand();
        insertSession.CommandText =
            "INSERT INTO sessions(session_hash,user_id,device_id,created_at,expires_at) " +
            "VALUES($hash,$user,$device,$created,$expires);";
        insertSession.Parameters.AddWithValue("$hash", HashToken(sessionToken));
        insertSession.Parameters.AddWithValue("$user", user.UserId);
        insertSession.Parameters.AddWithValue("$device", deviceId);
        insertSession.Parameters.AddWithValue("$created", nowText);
        insertSession.Parameters.AddWithValue("$expires", sessionExpires.ToString("O"));
        await insertSession.ExecuteNonQueryAsync(cancellationToken);

        var updateSeen = connection.CreateCommand();
        updateSeen.CommandText = "UPDATE devices SET last_seen_at=$seen WHERE device_id=$id;";
        updateSeen.Parameters.AddWithValue("$seen", nowText);
        updateSeen.Parameters.AddWithValue("$id", deviceId);
        await updateSeen.ExecuteNonQueryAsync(cancellationToken);
        var updateLogin = connection.CreateCommand();
        updateLogin.CommandText = "UPDATE users SET failed_attempts=0,locked_until=NULL,last_login_at=$now WHERE user_id=$id;";
        updateLogin.Parameters.AddWithValue("$now", nowText);
        updateLogin.Parameters.AddWithValue("$id", user.UserId);
        await updateLogin.ExecuteNonQueryAsync(cancellationToken);

        return (new LoginResult("authenticated", ToSummary(user with { MfaSecret = setup ? challenge.SetupSecret : user.MfaSecret }),
            sessionExpires, null), sessionToken, null);
    }

    public async Task<SessionIdentity?> GetSessionAsync(string sessionToken, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT s.session_hash,s.user_id,s.device_id,s.expires_at,u.display_name,u.email,u.role,u.status,u.mfa_secret,d.status,d.compliance_status " +
            "FROM sessions s JOIN users u ON u.user_id=s.user_id JOIN devices d ON d.device_id=s.device_id " +
            "WHERE s.session_hash=$hash;";
        command.Parameters.AddWithValue("$hash", HashToken(sessionToken));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var expiry = DateTimeOffset.Parse(reader.GetString(3));
        if (expiry <= now || reader.GetString(7) != "active" || reader.GetString(9) != "approved" ||
            (_requireCompliantWorkstations && reader.GetString(10) != "compliant") ||
            reader.IsDBNull(8))
        {
            reader.Close();
            await RevokeSessionAsync(sessionToken, cancellationToken);
            return null;
        }

        return new SessionIdentity(
            sessionToken,
            reader.GetString(1),
            reader.GetString(2),
            expiry,
            reader.GetString(4),
            reader.GetString(5),
            reader.GetString(6),
            MfaEnabled: true);
    }

    public async Task RevokeSessionAsync(string sessionToken, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM sessions WHERE session_hash=$hash;";
        command.Parameters.AddWithValue("$hash", HashToken(sessionToken));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<UserSummary?> GetUserSummaryAsync(string userId, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var user = await GetUserByIdAsync(connection, userId, cancellationToken);
        return user is null ? null : ToSummary(user);
    }

    public async Task<IReadOnlyList<UserSummary>> ListUsersAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = "SELECT user_id,display_name,email,role,status,password_hash,mfa_secret,created_at,last_login_at,failed_attempts,locked_until FROM users ORDER BY created_at DESC;";
        var users = new List<UserSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            users.Add(ToSummary(ReadUser(reader)));
        }

        return users;
    }

    public async Task<UserSummary> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken)
    {
        var email = request.Email.Trim();
        var role = request.Role.Trim().ToLowerInvariant();
        if (!email.Contains('@') || email.Length > 254 ||
            string.IsNullOrWhiteSpace(request.DisplayName) || request.DisplayName.Trim().Length > 100)
        {
            throw new ArgumentException("Enter a valid email and display name.");
        }

        if (role is not ("admin" or "setter" or "reviewer" or "investigator"))
        {
            throw new ArgumentException("Choose a valid account role.");
        }

        ValidatePassword(request.Password);
        await using var connection = await OpenAsync(cancellationToken);
        var id = await InsertUserAsync(connection, email, request.DisplayName.Trim(), role, request.Password, cancellationToken);
        var user = await GetUserByIdAsync(connection, id, cancellationToken);
        return ToSummary(user!);
    }

    public async Task<UserSummary?> SetUserStatusAsync(string userId, string status, CancellationToken cancellationToken)
    {
        if (status is not ("active" or "disabled"))
        {
            throw new ArgumentException("Status must be active or disabled.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        var target = await GetUserByIdAsync(connection, userId, cancellationToken);
        if (target is null)
        {
            return null;
        }

        if (status == "disabled" && target.Role == "admin" && target.Status == "active")
        {
            var count = connection.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM users WHERE role='admin' AND status='active';";
            if ((long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L) <= 1)
            {
                throw new InvalidOperationException("At least one active administrator must remain.");
            }
        }

        var update = connection.CreateCommand();
        update.CommandText = "UPDATE users SET status=$status WHERE user_id=$id;";
        update.Parameters.AddWithValue("$status", status);
        update.Parameters.AddWithValue("$id", userId);
        await update.ExecuteNonQueryAsync(cancellationToken);
        if (status == "disabled")
        {
            var revoke = connection.CreateCommand();
            revoke.CommandText = "DELETE FROM sessions WHERE user_id=$id;";
            revoke.Parameters.AddWithValue("$id", userId);
            await revoke.ExecuteNonQueryAsync(cancellationToken);
        }

        return await GetUserSummaryAsync(userId, cancellationToken);
    }

    public async Task<UserSummary?> SetUserRoleAsync(
        string userId,
        string role,
        string actorId,
        CancellationToken cancellationToken)
    {
        role = role.Trim().ToLowerInvariant();
        if (role is not ("admin" or "setter" or "reviewer" or "investigator"))
        {
            throw new ArgumentException("Choose a valid account role.");
        }

        if (userId == actorId)
        {
            throw new InvalidOperationException("You cannot change your own role.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        var target = await GetUserByIdAsync(connection, userId, cancellationToken);
        if (target is null)
        {
            return null;
        }

        if (target.Role == "admin" && target.Status == "active" && role != "admin")
        {
            var count = connection.CreateCommand();
            count.CommandText = "SELECT COUNT(*) FROM users WHERE role='admin' AND status='active';";
            if ((long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L) <= 1)
            {
                throw new InvalidOperationException("At least one active administrator must remain.");
            }
        }

        if (target.Role == role)
        {
            return ToSummary(target);
        }

        var update = connection.CreateCommand();
        update.CommandText = "UPDATE users SET role=$role WHERE user_id=$id;";
        update.Parameters.AddWithValue("$role", role);
        update.Parameters.AddWithValue("$id", userId);
        await update.ExecuteNonQueryAsync(cancellationToken);

        var revoke = connection.CreateCommand();
        revoke.CommandText = "DELETE FROM sessions WHERE user_id=$id;";
        revoke.Parameters.AddWithValue("$id", userId);
        await revoke.ExecuteNonQueryAsync(cancellationToken);
        return await GetUserSummaryAsync(userId, cancellationToken);
    }

    public async Task<bool> ResetMfaAsync(string userId, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var update = connection.CreateCommand();
        update.CommandText = "UPDATE users SET mfa_secret=NULL WHERE user_id=$id;";
        update.Parameters.AddWithValue("$id", userId);
        if (await update.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            return false;
        }

        var revoke = connection.CreateCommand();
        revoke.CommandText = "DELETE FROM sessions WHERE user_id=$id;";
        revoke.Parameters.AddWithValue("$id", userId);
        await revoke.ExecuteNonQueryAsync(cancellationToken);
        return true;
    }

    public async Task ChangePasswordAsync(
        string userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken)
    {
        ValidatePassword(newPassword);
        await using var connection = await OpenAsync(cancellationToken);
        var user = await GetUserByIdAsync(connection, userId, cancellationToken);
        if (user is null || !PasswordHasher.Verify(currentPassword, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Current password is incorrect.");
        }

        var update = connection.CreateCommand();
        update.CommandText = "UPDATE users SET password_hash=$hash,failed_attempts=0,locked_until=NULL WHERE user_id=$id;";
        update.Parameters.AddWithValue("$hash", PasswordHasher.Hash(newPassword));
        update.Parameters.AddWithValue("$id", userId);
        await update.ExecuteNonQueryAsync(cancellationToken);

        var revoke = connection.CreateCommand();
        revoke.CommandText = "DELETE FROM sessions WHERE user_id=$id;";
        revoke.Parameters.AddWithValue("$id", userId);
        await revoke.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<DeviceSummary>> ListDevicesAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "SELECT d.device_id,d.user_id,u.display_name,d.name,d.status,d.created_at,d.last_seen_at," +
            "d.centre,d.room,d.workstation_id,d.compliance_status,d.operating_system,d.application_control_detected," +
            "d.system_restrictions_configured,d.compliance_checked_at " +
            "FROM devices d JOIN users u ON u.user_id=d.user_id ORDER BY d.created_at DESC;";
        var devices = new List<DeviceSummary>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            devices.Add(new DeviceSummary(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                DateTimeOffset.Parse(reader.GetString(5)),
                reader.IsDBNull(6) ? null : DateTimeOffset.Parse(reader.GetString(6)),
                reader.GetString(7),
                reader.GetString(8),
                reader.GetString(9),
                reader.GetString(10),
                reader.GetString(11),
                reader.GetInt32(12) == 1,
                reader.GetInt32(13) == 1,
                reader.IsDBNull(14) ? null : DateTimeOffset.Parse(reader.GetString(14))));
        }

        return devices;
    }

    public async Task<bool> AssignWorkstationAsync(
        string deviceId,
        string centre,
        string room,
        string workstationId,
        CancellationToken cancellationToken)
    {
        if (!IsValidAssignment(centre, room, workstationId))
        {
            throw new ArgumentException("Centre, room, and workstation ID are required and must be 100 characters or fewer.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText =
            "UPDATE devices SET centre=$centre,room=$room,workstation_id=$workstationId WHERE device_id=$id;";
        command.Parameters.AddWithValue("$centre", centre.Trim());
        command.Parameters.AddWithValue("$room", room.Trim());
        command.Parameters.AddWithValue("$workstationId", workstationId.Trim());
        command.Parameters.AddWithValue("$id", deviceId);
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<bool> SetDeviceStatusAsync(string deviceId, string status, CancellationToken cancellationToken)
    {
        if (status is not ("approved" or "revoked"))
        {
            throw new ArgumentException("Device status must be approved or revoked.");
        }

        await using var connection = await OpenAsync(cancellationToken);
        var command = connection.CreateCommand();
        command.CommandText = "UPDATE devices SET status=$status WHERE device_id=$id;";
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$id", deviceId);
        var changed = await command.ExecuteNonQueryAsync(cancellationToken) > 0;
        if (changed && status == "revoked")
        {
            var revokeSessions = connection.CreateCommand();
            revokeSessions.CommandText = "DELETE FROM sessions WHERE device_id=$id;";
            revokeSessions.Parameters.AddWithValue("$id", deviceId);
            await revokeSessions.ExecuteNonQueryAsync(cancellationToken);
        }

        return changed;
    }

    private async Task<string> InsertUserAsync(
        SqliteConnection connection,
        string email,
        string displayName,
        string role,
        string password,
        CancellationToken cancellationToken)
    {
        var id = $"USR-{Guid.NewGuid():N}";
        var command = connection.CreateCommand();
        command.CommandText =
            "INSERT INTO users(user_id,display_name,email,role,status,password_hash,created_at) " +
            "VALUES($id,$name,$email,$role,'active',$hash,$created);";
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$name", displayName);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$hash", PasswordHasher.Hash(password));
        command.Parameters.AddWithValue("$created", DateTimeOffset.UtcNow.ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken);
        return id;
    }

    private async Task<UserRecord?> GetUserByEmailAsync(SqliteConnection connection, string email, CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT user_id,display_name,email,role,status,password_hash,mfa_secret,created_at,last_login_at,failed_attempts,locked_until FROM users WHERE email=$email COLLATE NOCASE;";
        command.Parameters.AddWithValue("$email", email.Trim());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadUser(reader) : null;
    }

    private async Task<UserRecord?> GetUserByIdAsync(SqliteConnection connection, string userId, CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT user_id,display_name,email,role,status,password_hash,mfa_secret,created_at,last_login_at,failed_attempts,locked_until FROM users WHERE user_id=$id;";
        command.Parameters.AddWithValue("$id", userId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadUser(reader) : null;
    }

    private static UserRecord ReadUser(SqliteDataReader reader) =>
        new(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetString(6),
            DateTimeOffset.Parse(reader.GetString(7)),
            reader.IsDBNull(8) ? null : DateTimeOffset.Parse(reader.GetString(8)),
            reader.GetInt32(9),
            reader.IsDBNull(10) ? null : DateTimeOffset.Parse(reader.GetString(10)));

    private async Task<ChallengeRecord?> GetChallengeAsync(
        SqliteConnection connection,
        string challengeId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT challenge_hash,user_id,setup_secret,expires_at,failed_attempts FROM login_challenges WHERE challenge_hash=$hash;";
        command.Parameters.AddWithValue("$hash", HashToken(challengeId));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var record = new ChallengeRecord(
            reader.GetString(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            DateTimeOffset.Parse(reader.GetString(3)),
            reader.GetInt32(4));
        if (record.ExpiresAt <= now || record.FailedAttempts >= 5)
        {
            reader.Close();
            var delete = connection.CreateCommand();
            delete.CommandText = "DELETE FROM login_challenges WHERE challenge_hash=$hash;";
            delete.Parameters.AddWithValue("$hash", record.ChallengeHash);
            await delete.ExecuteNonQueryAsync(cancellationToken);
            return null;
        }

        return record;
    }

    private async Task<DeviceRecord?> GetDeviceAsync(SqliteConnection connection, string deviceId, CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT device_id,user_id,name,secret_hash,status FROM devices WHERE device_id=$id;";
        command.Parameters.AddWithValue("$id", deviceId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new DeviceRecord(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4))
            : null;
    }

    private static async Task DeleteChallengeAsync(SqliteConnection connection, string challengeId, CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM login_challenges WHERE challenge_hash=$hash;";
        command.Parameters.AddWithValue("$hash", HashToken(challengeId));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task RecordFailedLoginAsync(
        SqliteConnection connection,
        string userId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText =
            "UPDATE users SET failed_attempts=failed_attempts+1," +
            "locked_until=CASE WHEN failed_attempts+1>=5 THEN $locked ELSE locked_until END WHERE user_id=$id;";
        command.Parameters.AddWithValue("$locked", now.AddMinutes(15).ToString("O"));
        command.Parameters.AddWithValue("$id", userId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task IncrementChallengeFailureAsync(
        SqliteConnection connection,
        string challengeId,
        int attempts,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "UPDATE login_challenges SET failed_attempts=$attempts WHERE challenge_hash=$hash;";
        command.Parameters.AddWithValue("$attempts", attempts + 1);
        command.Parameters.AddWithValue("$hash", HashToken(challengeId));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static bool IsValidDeviceInput(string deviceId, string deviceName, string deviceSecret) =>
        Guid.TryParse(deviceId, out _) &&
        !string.IsNullOrWhiteSpace(deviceName) &&
        deviceName.Trim().Length <= 100 &&
        deviceSecret.Length >= 32 &&
        deviceSecret.Length <= 256;

    private static bool IsValidWorkstationPolicy(WorkstationPolicyReport? report) =>
        report is not null &&
        !string.IsNullOrWhiteSpace(report.OperatingSystem) &&
        report.OperatingSystem.Length <= 200;

    private static bool IsCompliant(WorkstationPolicyReport report) =>
        report.Windows && report.ApplicationControlPolicyDetected && report.SystemRestrictionsConfigured;

    private static bool IsValidAssignment(string centre, string room, string workstationId) =>
        !string.IsNullOrWhiteSpace(centre) && centre.Trim().Length <= 100 &&
        !string.IsNullOrWhiteSpace(room) && room.Trim().Length <= 100 &&
        !string.IsNullOrWhiteSpace(workstationId) && workstationId.Trim().Length <= 100;

    private static void AddPolicyParameters(
        SqliteCommand command,
        WorkstationPolicyReport report,
        DateTimeOffset checkedAt)
    {
        command.Parameters.AddWithValue("$os", report.OperatingSystem.Trim());
        command.Parameters.AddWithValue("$appControl", report.ApplicationControlPolicyDetected ? 1 : 0);
        command.Parameters.AddWithValue("$systemRestrictions", report.SystemRestrictionsConfigured ? 1 : 0);
        command.Parameters.AddWithValue("$compliance", IsCompliant(report) ? "compliant" : "noncompliant");
        command.Parameters.AddWithValue("$checked", checkedAt.ToString("O"));
    }

    private static async Task SaveWorkstationPolicyAsync(
        SqliteConnection connection,
        string deviceId,
        WorkstationPolicyReport report,
        DateTimeOffset checkedAt,
        CancellationToken cancellationToken)
    {
        var update = connection.CreateCommand();
        update.CommandText =
            "UPDATE devices SET operating_system=$os,application_control_detected=$appControl," +
            "system_restrictions_configured=$systemRestrictions,compliance_status=$compliance," +
            "compliance_checked_at=$checked WHERE device_id=$id;";
        AddPolicyParameters(update, report, checkedAt);
        update.Parameters.AddWithValue("$id", deviceId);
        await update.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureDeviceColumnAsync(
        SqliteConnection connection,
        string columnName,
        string columnDefinition,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(devices);";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.GetString(1) == columnName)
            {
                return;
            }
        }

        reader.Close();
        var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE devices ADD COLUMN {columnName} {columnDefinition};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<bool> DeviceColumnExistsAsync(
        SqliteConnection connection,
        string columnName,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(devices);";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.GetString(1) == columnName)
            {
                return true;
            }
        }

        return false;
    }

    private static string NewToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static void ValidatePassword(string password)
    {
        if (password.Length < 14 || password.Length > 256 ||
            !password.Any(char.IsLetter) || !password.Any(char.IsDigit))
        {
            throw new ArgumentException("Passwords must be 14–256 characters and include letters and numbers.");
        }
    }

    private static UserSummary ToSummary(UserRecord user) =>
        new(user.UserId, user.DisplayName, user.Email, user.Role, user.Status,
            user.MfaSecret is not null, user.CreatedAt, user.LastLoginAt);

    private sealed record UserRecord(
        string UserId,
        string DisplayName,
        string Email,
        string Role,
        string Status,
        string PasswordHash,
        string? MfaSecret,
        DateTimeOffset CreatedAt,
        DateTimeOffset? LastLoginAt,
        int FailedAttempts,
        DateTimeOffset? LockedUntil);

    private sealed record ChallengeRecord(
        string ChallengeHash,
        string UserId,
        string? SetupSecret,
        DateTimeOffset ExpiresAt,
        int FailedAttempts);

    private sealed record DeviceRecord(string DeviceId, string UserId, string Name, string SecretHash, string Status);
}
