namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Interface for an object that provides the current authentication scheme's user and strategy
    /// </summary>
    public interface IAuthContext
    {
        IAuthStrategy GetAuthStrategy(AuthenticationType? authType = null);
        ICurrentUser GetCurrentUser(AuthenticationType? authType = null);
    }
}
