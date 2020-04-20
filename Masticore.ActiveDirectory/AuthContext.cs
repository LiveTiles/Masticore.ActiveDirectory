using Masticore.Mvc;
using System.Web;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Class for pulling the ICurrentUser and IAuthStrategy per the current context
    /// TODO: Refactor out the use of the "AppSettings" class and make this portable across portal and infrastructure apps
    /// </summary>
    public class AuthContext : IAuthContext
    {
        /// <summary>
        /// Gets the ICurrentUser implementor for the current authentrication type
        /// </summary>
        /// <returns></returns>
        public virtual ICurrentUser GetCurrentUser(AuthenticationType? authType = null)
        {
            if (!authType.HasValue)
                authType = HttpContext.Current.GetAuthenticationType();

            switch (authType)
            {
                case AuthenticationType.Okta:
                    return new OktaUser();

                case AuthenticationType.ActiveDirectory:
                case AuthenticationType.ActiveDirectoryB2C:
                default:
                    return new ActiveDirectoryUser();
            }
        }

        /// <summary>
        /// Gets the current auth strategy for the given or current authentication type
        /// </summary>
        /// <param name="authType"></param>
        /// <returns></returns>
        public virtual IAuthStrategy GetAuthStrategy(AuthenticationType? authType = null)
        {
            if (!authType.HasValue)
                authType = HttpContext.Current.GetAuthenticationType();

            switch (authType)
            {
                case AuthenticationType.Okta:
                    return new OktaStrategy();

                case AuthenticationType.ActiveDirectoryB2C:
                    return new B2CStrategy();

                case AuthenticationType.ActiveDirectory:
                default:
                    return new OrgStrategy();
            }
        }
    }
}
