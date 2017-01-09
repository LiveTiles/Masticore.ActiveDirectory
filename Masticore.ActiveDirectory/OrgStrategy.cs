using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Implements IActiveDirectoryIntegration over Organization/School Active Directory style
    /// Reads ClientId and AADInstance from ActiveDirectoryAppSettings
    /// </summary>
    public class OrgStrategy : IActiveDirectoryStrategy
    {
        #region App Settings

        /// <summary>
        /// GUID for the application ID
        /// This is set in the AD portal
        /// </summary>
        public static readonly string ClientId = ActiveDirectoryAppSettings.ClientId;

        /// <summary>
        /// URL for the signin server, EG: https://login.microsoftonline.com/
        /// </summary>
        public static readonly string AADInstance = ActiveDirectoryAppSettings.AADInstance + "common";

        #endregion

        /// <summary>
        /// Configures anti-forgery validatation to use the OID of the current user
        /// </summary>
        protected virtual void ConfigureAntiForgeryValidation()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        }

        #region IActiveDirectoryStrategy Implementation

        /// <summary>
        /// Configures the app to use the Org-style AD integration
        /// </summary>
        /// <param name="app"></param>
        public virtual void Configure(IAppBuilder app)
        {
            ConfigureAntiForgeryValidation();

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions { });

            app.UseOpenIdConnectAuthenticationPatched(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = ClientId,
                    Authority = AADInstance,
                    TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                    {
                        // instead of using the default validation (validating against a single issuer value, as we do in line of business apps), 
                        // we inject our own multitenant validation logic
                        ValidateIssuer = false,
                        // If the app needs access to the entire organization, then add the logic
                        // of validating the Issuer here.
                        // IssuerValidator
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        SecurityTokenValidated = (context) =>
                        {
                            // If your authentication logic is based on users then add your logic here
                            return Task.FromResult(0);
                        },
                        AuthenticationFailed = (context) =>
                        {
                            // Pass in the context back to the app
                            context.OwinContext.Response.Redirect("/Home/Error");
                            context.HandleResponse(); // Suppress the exception
                            return Task.FromResult(0);
                        }
                    }
                });
        }

        /// <summary>
        /// Signs in the current user, then redirects them to the given URI
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public virtual void SignIn(Controller controller, string redirectUri)
        {
            controller.HttpContext.GetOwinContext().Authentication.Challenge(new
                AuthenticationProperties
            {
                RedirectUri = redirectUri
            },
                OpenIdConnectAuthenticationDefaults.AuthenticationType);
        }

        /// <summary>
        /// For Org accounts, there is no signup, only signin, so this is the same as sign-in
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public virtual void SignUp(Controller controller, string redirectUri)
        {
            SignIn(controller, redirectUri);
        }

        /// <summary>
        /// Logs the current user out of the system
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public virtual void SignOut(Controller controller, string redirectUri)
        {
            controller.HttpContext.GetOwinContext().Authentication.SignOut(
                new AuthenticationProperties { RedirectUri = redirectUri },
                OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
        }

        #endregion
    }
}
