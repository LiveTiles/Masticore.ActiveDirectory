using Masticore;
using Masticore.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Okta.AspNet;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Implements an auth strategy for Okta
    /// Default configuration is taken from config file
    /// Learn More: https://www.okta.com/
    /// Dev Docs: https://developer.okta.com/code/dotnet/aspnet/
    /// </summary>
    public class OktaStrategy : IAuthStrategy
    {
        /// <summary>
        /// Gets or sets the Okta Domain
        /// The domain comes paired with the app registration and should vary by organization
        /// By default, this is set to "okta:OktaDomain" from the config file
        /// </summary>
        public string Domain { get; set; } = ConfigurationManager.AppSettings["okta:OktaDomain"];

        /// <summary>
        /// Gets or sets the Client ID for this app
        /// The client ID identifies the app inside of the Okta Domain
        /// By default, this is set to "okta:ClientId" from the config file
        /// </summary>
        public string ClientId { get; set; } = ConfigurationManager.AppSettings["okta:ClientId"];

        /// <summary>
        /// Gets or sets the client secret
        /// This is coupled to the ClientID
        /// By default, this is set to "okta:ClientSecret" from the config file
        /// </summary>
        public string ClientSecret { get; set; } = ConfigurationManager.AppSettings["okta:ClientSecret"];

        /// <summary>
        /// Gets or sets the redirect Url
        /// This must match the settings in the Okta app
        /// By default, this is set to "okta:RedirectUri" from the config file
        /// </summary>
        public string RedirectUrl { get; set; } = ConfigurationManager.AppSettings["okta:RedirectUri"];

        /// <summary>
        /// Gets or sets the post logout redirect Url
        /// This must match the settings in the Okta app
        /// By default, this is set to "okta:PostLogoutRedirectUri" from the config file
        /// </summary>
        public string PostLogoutUrl { get; set; } = ConfigurationManager.AppSettings["okta:PostLogoutRedirectUri"];

        /// <summary>
        /// Not Implemented in Okta
        /// </summary>
        public string SignInPolicyId { get; set; }

        /// <summary>
        /// Not Implemented in Okta
        /// </summary>
        public string SignUpPolicyId { get; set; }

        /// <summary>
        /// Not Implemented in Okta
        /// </summary>
        public string ProfilePolicyId { get; set; }

        /// <summary>
        /// Configures the given app to utilize Okta
        /// </summary>
        /// <param name="app"></param>
        public void Configure(IAppBuilder app)
        {
            // Enable TLS 1.2
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOktaMvc(new OktaMvcOptions()
            {
                OktaDomain = Domain,
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                RedirectUri = RedirectUrl,
                PostLogoutRedirectUri = PostLogoutUrl,
                Scope = new List<string> { "openid", "profile", "email" },
                LoginMode = LoginMode.OktaHosted,
            });

            app.Use((context, next) =>
            {
                context.SetAuthenticationType(AuthenticationType.Okta);
                return next();
            });
        }

        /// <summary>
        /// Not Implemented in Okta
        /// </summary>
        public Task<string> GetAuthenticationTokenAsync()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Challenges the current user to sign-in via OWIN
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public void SignIn(Controller controller, string redirectUri)
        {
            HttpContext.Current.GetOwinContext().Authentication.Challenge(
                new AuthenticationProperties() { RedirectUri = redirectUri },
                    OktaDefaults.MvcAuthenticationType);
        }

        /// <summary>
        /// Signs out the current user via OWIN
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public void SignOut(Controller controller, string redirectUri)
        {
            HttpContext.Current.GetOwinContext().Authentication.SignOut(
                   CookieAuthenticationDefaults.AuthenticationType,
                   OktaDefaults.MvcAuthenticationType);
        }

        /// <summary>
        /// Not implemented in Okta
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        public void SignUp(Controller controller, string redirectUri)
        {
            throw new NotImplementedException();
        }
    }
}
