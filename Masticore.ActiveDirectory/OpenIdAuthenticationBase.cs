using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Linq;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// This is a workaround Owin.OpenIdAuthenticaton issue that is specific for OWIN 3.0.1. 
    /// It should be patched for ASP.NET CORE, but we need it for now to prevent the 400 Request Headers Too Long issue. 
    /// https://github.com/aspnet/Security/issues/179
    /// </summary>
    public static class OpenIdConnectAuthenticationPatchedMiddlewareExtension
    {
        /// <summary>
        /// Sets the "app.Use" for the OpenId implemementatio
        /// </summary>
        /// <param name="app">The IAppBuilder implementation</param>
        /// <param name="openIdConnectOptions">The OpenIdConnectAuthenticationOptions such as ClientId, etc. </param>
        /// <returns>The IAppBuilder</returns>
        public static Owin.IAppBuilder UseOpenIdConnectAuthenticationPatched(this Owin.IAppBuilder app, Microsoft.Owin.Security.OpenIdConnect.OpenIdConnectAuthenticationOptions openIdConnectOptions)
        {
            if (app == null)
            {
                throw new System.ArgumentNullException("app");
            }
            if (openIdConnectOptions == null)
            {
                throw new System.ArgumentNullException("openIdConnectOptions");
            }
            var type = typeof(OpenIdConnectAuthenticationPatchedMiddleware);
            var objArray = new object[] { app, openIdConnectOptions };
            return app.Use(type, objArray);
        }
    }

    /// <summary>
    /// Patched to fix the issue with too many nonce cookies described here: https://github.com/IdentityServer/IdentityServer3/issues/1124
    /// This is an Owin.OpenIdAuthenticaton issue that is specific for OWIN 3.0.1.
    /// Deletes all nonce cookies that weren't the current one
    /// </summary>
    public class OpenIdConnectAuthenticationPatchedMiddleware : OpenIdConnectAuthenticationMiddleware
    {
        private readonly Microsoft.Owin.Logging.ILogger _logger;

        public OpenIdConnectAuthenticationPatchedMiddleware(Microsoft.Owin.OwinMiddleware next, Owin.IAppBuilder app, Microsoft.Owin.Security.OpenIdConnect.OpenIdConnectAuthenticationOptions options)
                : base(next, app, options)
        {
            this._logger = Microsoft.Owin.Logging.AppBuilderLoggerExtensions.CreateLogger<OpenIdConnectAuthenticationPatchedMiddleware>(app);
        }

        /// <summary>
        /// Override the base implementation of Infrastructure.AuthenticationHandler
        /// </summary>
        /// <returns>OpenIdConnectAuthenticationHandler</returns>
        protected override Microsoft.Owin.Security.Infrastructure.AuthenticationHandler<OpenIdConnectAuthenticationOptions> CreateHandler()
        {
            return new MasticoreOpenIdConnectAuthenticationHandler(_logger);
        }

        public class MasticoreOpenIdConnectAuthenticationHandler : OpenIdConnectAuthenticationHandler
        {
            public MasticoreOpenIdConnectAuthenticationHandler(Microsoft.Owin.Logging.ILogger logger)
                : base(logger) { }

            /// <summary>
            /// Override the mechanism that saves the Owin Cookie (issue where the nonce is repeatly set, overflowing the request handler)
            /// </summary>
            /// <param name="message">The OpenId Request message</param>
            /// <param name="nonce">The nonce value, typically a secure cookie</param>
            protected override void RememberNonce(OpenIdConnectMessage message, string nonce)
            {
                var oldNonces = Request.Cookies.Where(kvp => kvp.Key.StartsWith(OpenIdConnectAuthenticationDefaults.CookiePrefix + "nonce"));
               
                if (oldNonces.Any())
                {
                    var cookieOptions = new Microsoft.Owin.CookieOptions
                    {
                        HttpOnly = true,
                        Secure = Request.IsSecure
                    };
                    foreach (var oldNonce in oldNonces)
                    {
                        Response.Cookies.Delete(oldNonce.Key, cookieOptions);
                    }
                }
                base.RememberNonce(message, nonce);
            }
        }
    }

}
