using System.Security.Cryptography;
using System.Text;

namespace SecureExam.Api.Security;

internal static class Totp
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string NewSecret()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        return Convert.ToBase64String(bytes);
    }

    public static string ToBase32(string base64Secret) =>
        EncodeBase32(Convert.FromBase64String(base64Secret));

    public static bool TryVerify(string base64Secret, string code, DateTimeOffset now, out long matchedStep)
    {
        matchedStep = -1;
        if (code.Length != 6 || code.Any(character => !char.IsDigit(character)))
        {
            return false;
        }

        var key = Convert.FromBase64String(base64Secret);
        var currentStep = now.ToUnixTimeSeconds() / 30;
        for (var offset = -1; offset <= 1; offset++)
        {
            var step = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(currentStep + offset));
            using var hmac = new HMACSHA1(key);
            var hash = hmac.ComputeHash(step);
            var index = hash[^1] & 0x0f;
            var binary = ((hash[index] & 0x7f) << 24) |
                         ((hash[index + 1] & 0xff) << 16) |
                         ((hash[index + 2] & 0xff) << 8) |
                         (hash[index + 3] & 0xff);
            var expected = (binary % 1_000_000).ToString("D6");
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(code)))
            {
                matchedStep = currentStep + offset;
                return true;
            }
        }

        return false;
    }

    private static string EncodeBase32(byte[] bytes)
    {
        var result = new StringBuilder();
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var value in bytes)
        {
            buffer = (buffer << 8) | value;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                result.Append(Alphabet[(buffer >> (bitsLeft - 5)) & 31]);
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
        {
            result.Append(Alphabet[(buffer << (5 - bitsLeft)) & 31]);
        }

        return result.ToString();
    }
}
