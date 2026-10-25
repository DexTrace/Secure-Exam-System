using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;
using SecureExam.Desktop.Models;

namespace SecureExam.Desktop.Services;

internal sealed class DeviceIdentity
{
    private const string Entropy = "SecureExam.Desktop.Device.v1";
    private DeviceIdentity(string deviceId, string name, string secret)
    {
        DeviceId = deviceId;
        Name = name;
        Secret = secret;
    }

    public string DeviceId { get; }
    public string Name { get; }
    public string Secret { get; }

    public static DeviceIdentity LoadOrCreate()
    {
        var directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecureExamSystem");
        Directory.CreateDirectory(directory);
        var identityPath = Path.Combine(directory, "device.identity");

        if (File.Exists(identityPath))
        {
            try
            {
                var protectedData = File.ReadAllBytes(identityPath);
                var data = ProtectedData.Unprotect(
                    protectedData,
                    Encoding.UTF8.GetBytes(Entropy),
                    DataProtectionScope.CurrentUser);
                var saved = JsonSerializer.Deserialize<SavedIdentity>(data);
                if (saved is not null && Guid.TryParse(saved.DeviceId, out _) && saved.Secret.Length >= 32)
                {
                    return new DeviceIdentity(saved.DeviceId, saved.Name, saved.Secret);
                }
            }
            catch (Exception exception) when (exception is CryptographicException or JsonException or IOException)
            {
                throw new InvalidOperationException(
                    "The saved workstation identity could not be decrypted. Do not delete it if this device is already approved; contact an administrator to re-enroll this workstation.",
                    exception);
            }
        }

        var identity = new SavedIdentity(
            Guid.NewGuid().ToString(),
            Environment.MachineName,
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(identity);
        var encrypted = ProtectedData.Protect(
            plaintext,
            Encoding.UTF8.GetBytes(Entropy),
            DataProtectionScope.CurrentUser);
        File.WriteAllBytes(identityPath, encrypted);
        return new DeviceIdentity(identity.DeviceId, identity.Name, identity.Secret);
    }

    private sealed record SavedIdentity(string DeviceId, string Name, string Secret);
}
