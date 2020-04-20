using Microsoft.Owin;
using System.Web;

namespace Masticore.ActiveDirectory
{
    public static class AuthHelper
    {
        public const string AuthTypeKey = "AuthType";

        public static void SetAuthenticationType(this IOwinContext context, AuthenticationType authType)
        {
            context.Set<AuthenticationType>(AuthTypeKey, authType);
        }

        public static AuthenticationType GetAuthenticationType(this IOwinContext context)
        {
            return context.Get<AuthenticationType>(AuthTypeKey);
        }

        public static AuthenticationType GetAuthenticationType(this HttpContext context)
        {
            return context.GetOwinContext().GetAuthenticationType();
        }
    }
}
