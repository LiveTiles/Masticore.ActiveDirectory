using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Implements the B2C style integration for Azure Active Directory (e-mail/password, LinkedIn, Microsoft, Facebook, etc)
    /// NOTE:
    /// When using the B2C strategy with two separate web apps, it seems to be necessary to do a logout from the first one then redirect to the second one;
    /// otherwise, IE and Edge will get stuck in a redirect loop. For example, in an ASP.Net MVC Controller:
    /// B2CStrategy strategy = new B2CStrategy();
    /// strategy.SignOut(this, "[Other App URL]");
    /// </summary>
    public class B2CStrategy : IActiveDirectoryStrategy
    {
        // App config settings
        public static readonly string ClientId = ActiveDirectoryAppSettings.ClientId;
        public static readonly string AadInstance = ActiveDirectoryAppSettings.AADInstance;
        public const string OAuthForAadInstance = "{0}/v2.0/.well-known/openid-configuration?p={1}";
        public static readonly string Domain = ActiveDirectoryAppSettings.Domain;
        public static readonly string RedirectUri = ActiveDirectoryAppSettings.RedirectUri;

        // B2C policy identifiers
        public static readonly string SignInPolicyId = ActiveDirectoryAppSettings.SignInPolicyId;
        public static readonly string SignUpPolicyId = ActiveDirectoryAppSettings.SignUpPolicyId;
        public static readonly string ProfilePolicyId = ActiveDirectoryAppSettings.UserProfilePolicyId;

        /// <summary>
        /// Called when authentication process fails
        /// </summary>
        /// <param name="notification"></param>
        /// <returns></returns>
        protected virtual Task AuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            // TODO: Make this runtime configurable in some way for better flexibility
            if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Creates a OpenIdConnectAuthenticationOptions for the given policy using the current web.config settings
        /// </summary>
        /// <param name="policy"></param>
        /// <returns></returns>
        protected virtual OpenIdConnectAuthenticationOptions CreateOptionsFromPolicy(string policy)
        {
            // Add to the Aad Instance the pre-defined OAuth 2
            string metaAddressFormat = AadInstance + OAuthForAadInstance;

            // Force HTTPS redirect to prevent looping
            var builder = new UriBuilder(RedirectUri);
            builder.Scheme = "https";
            string httpsRedirectUri = builder.ToString();

            // Create and return auth options
            return new OpenIdConnectAuthenticationOptions
            {
                // For each policy, give OWIN the policy-specific metadata address, and
                // set the authentication type to the id of the policy
                MetadataAddress = string.Format(metaAddressFormat, Domain, policy),
                AuthenticationType = policy,

                // These are standard OpenID Connect parameters, with values pulled from web.config
                ClientId = ClientId,
                RedirectUri = httpsRedirectUri,
                PostLogoutRedirectUri = httpsRedirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = AuthenticationFailed,
                },
                Scope = "openid",
                ResponseType = "id_token",

                // This piece is optional - it is used for displaying the user's name in the navigation bar.
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                },
            };
        }

        /// <summary>
        /// Configures the strategy for AntiForgeryConfig - By default this is the OID claim for the user
        /// </summary>
        protected virtual void ConfigureAntiForgeryValidation()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        }

        /// <summary>
        /// Runs the Profile action, taking the current user to the page for their profile in AD B2C
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public virtual void Profile(Controller controller, string redirectUri)
        {
            controller.HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties() { RedirectUri = redirectUri }, ProfilePolicyId);
        }

        #region IActiveDirectoryStrategy Implementation

        /// <summary>
        /// Configures the current application to run the B2C connections
        /// </summary>
        /// <param name="app"></param>
        public virtual void Configure(IAppBuilder app)
        {
            ConfigureAntiForgeryValidation();

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            // TODO: Find a better workaround for infinite loop redirect issue
            // This is theoretically safe as long as we are forcing HTTPS redirect
            // (RequireSecureConnection Attribute + HTTPS URL Rewrite)
            // MSDN warning for "Always" setting: https://msdn.microsoft.com/en-us/library/microsoft.owin.security.cookies.cookiesecureoption(v=vs.113).aspx
            // HTTPS rewrite in web.config example, use this in the production app: https://gist.github.com/eralston/e487ef97edcad4881401
            // Issues on Stack Overflow: https://stackoverflow.com/questions/27525573/azure-openid-connect-via-owin-middleware-resulting-in-infinite-redirect-loop
            app.UseCookieAuthentication(new CookieAuthenticationOptions() { CookieSecure = CookieSecureOption.Always, CookieManager = new SystemWebCookieManager() });

            ConfiguratePolicies(app);
        }

        /// <summary>
        /// Attempts to setup the given policy in the app
        /// This will abort if the policyId is null or empty
        /// </summary>
        /// <param name="app"></param>
        /// <param name="policyId"></param>
        protected virtual void UsePolicy(IAppBuilder app, string policyId)
        {
            if (string.IsNullOrEmpty(policyId))
                return;

            app.UseOpenIdConnectAuthenticationPatched(CreateOptionsFromPolicy(policyId));
        }

        /// <summary>
        /// Configures available policies in the system
        /// </summary>
        /// <param name="app"></param>
        protected virtual void ConfiguratePolicies(IAppBuilder app)
        {
            UsePolicy(app, SignUpPolicyId);
            UsePolicy(app, ProfilePolicyId);
            // The last registered policy becomes the default policy
            UsePolicy(app, SignInPolicyId);
        }

        /// <summary>
        /// Signs in the current user
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public virtual void SignIn(Controller controller, string redirectUri)
        {
            // To execute a policy, you simply need to trigger an OWIN challenge.
            // You can indicate which policy to use by specifying the policy id as the AuthenticationType
            controller.HttpContext.GetOwinContext().Authentication.Challenge(
                new AuthenticationProperties() { RedirectUri = redirectUri }, SignInPolicyId);
        }

        /// <summary>
        /// Signs up the current user, creating a new account
        /// NOTE: You must implement your own user models and permissions, this is just authentication
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public virtual void SignUp(Controller controller, string redirectUri)
        {
            // To execute a policy, you simply need to trigger an OWIN challenge.
            // You can indicate which policy to use by specifying the policy id as the AuthenticationType
            controller.HttpContext.GetOwinContext().Authentication.Challenge(
                new AuthenticationProperties() { RedirectUri = redirectUri }, SignUpPolicyId);
        }

        /// <summary>
        /// Logs the current user out of the system
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public virtual void SignOut(Controller controller, string redirectUri)
        {
            IEnumerable<AuthenticationDescription> authTypes = controller.HttpContext.GetOwinContext().Authentication.GetAuthenticationTypes();
            controller.HttpContext.GetOwinContext().Authentication.SignOut(new AuthenticationProperties() { RedirectUri = redirectUri }, authTypes.Select(t => t.AuthenticationType).ToArray());
            controller.Request.GetOwinContext().Authentication.GetAuthenticationTypes();
        }

        #endregion
    }
}