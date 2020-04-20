using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Tokens;
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
    public class OrgStrategy : IAuthStrategy
    {
        public string ClientId { get; set; } = ActiveDirectoryAppSettings.ClientId;
        public string ClientSecret { get; set; } = ActiveDirectoryAppSettings.ClientSecret;

        public static readonly string AADInstance = ActiveDirectoryAppSettings.AADInstance + "common";

        public string RedirectUrl { get; set; }
        public string PostLogoutUrl { get; set; }
        public string SignInPolicyId { get; set; } = null;
        public string SignUpPolicyId { get; set; } = null;
        public string ProfilePolicyId { get; set; } = null;
        public string Domain { get; set; } = null;

        /// <summary>
        /// Configures anti-forgery validatation to use the OID of the current user
        /// </summary>
        protected virtual void ConfigureAntiForgeryValidation()
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = "http://schemas.microsoft.com/identity/claims/objectidentifier";
            AntiForgeryConfig.AdditionalDataProvider = new ActiveDirectoryAntiForgeryProvider();
        }

        /// <summary>
        /// Configures the app to use the Org-style AD integration
        /// </summary>
        /// <param name="app"></param>
        public virtual void Configure(IAppBuilder app)
        {
            ConfigureAntiForgeryValidation();

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions() { CookieSecure = CookieSecureOption.Always, CookieManager = new SameSiteCookieManager() });

            app.UseOpenIdConnectAuthenticationPatched(SetOptions());

            app.Use((context, next) =>
            {
                context.SetAuthenticationType(AuthenticationType.ActiveDirectory);
                return next();
            });
        }

        private OpenIdConnectAuthenticationOptions SetOptions()
        {
            var opts = new OpenIdConnectAuthenticationOptions
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                Authority = AADInstance,
                TokenValidationParameters = new TokenValidationParameters
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
                    },
                    RedirectToIdentityProvider = (context) =>
                    {
                        context.ProtocolMessage.Parameters.Add("msaFed", "0");
                        if (!string.IsNullOrEmpty(PostLogoutUrl))
                        {
                            context.ProtocolMessage.PostLogoutRedirectUri = PostLogoutUrl;
                        }
                        return Task.FromResult(0);
                    },
                }
            };

            if (!string.IsNullOrEmpty(RedirectUrl))
            {
                opts.RedirectUri = RedirectUrl;
            }

            //if (!string.IsNullOrEmpty(PostLogoutUrl))
            //{
            //    opts.PostLogoutRedirectUri = PostLogoutUrl;
            //}
            return opts;
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

        public async Task<string> GetAuthenticationTokenAsync()
        {

            var resource = "https://graph.microsoft.com/";

            var authority = AADInstance;
            var authContext = new AuthenticationContext(authority);
            var credentials = new ClientCredential(ClientId, ClientSecret);
            var authResult = await authContext.AcquireTokenAsync(resource, credentials);

            return authResult.AccessToken;

        }
    }
}
