namespace SecureExam.Desktop.Services;

internal class ApiRequestException : Exception
{
    public ApiRequestException(string message) : base(message)
    {
    }
}

internal sealed class SessionExpiredException : ApiRequestException
{
    public SessionExpiredException(string message) : base(message)
    {
    }
}
