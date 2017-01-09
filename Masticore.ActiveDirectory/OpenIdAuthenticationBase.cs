using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// This is a workaround Owin.OpenIdAuthenticaton issue that is specific for OWIN 3.0.1. 
    /// It should be patched for ASP.NET CORE, but we need it for now to prevent the 400 Request Headers Too Long issue. 
    /// https://github.com/aspnet/Security/issues/179
    /// </summary>
    public static class OpenIdConnectAuthenticationPatchedMiddlewareExtension
    {
        
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
            System.Type type = typeof(OpenIdConnectAuthenticationPatchedMiddleware);
            object[] objArray = new object[] { app, openIdConnectOptions };
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

        protected override Microsoft.Owin.Security.Infrastructure.AuthenticationHandler<OpenIdConnectAuthenticationOptions> CreateHandler()
        {
            return new MasticoreOpenIdConnectAuthenticationHandler(_logger);
        }

        public class MasticoreOpenIdConnectAuthenticationHandler : OpenIdConnectAuthenticationHandler
        {
            public MasticoreOpenIdConnectAuthenticationHandler(Microsoft.Owin.Logging.ILogger logger)
                : base(logger) { }

            protected override void RememberNonce(OpenIdConnectMessage message, string nonce)
            {
                var oldNonces = Request.Cookies.Where(kvp => kvp.Key.StartsWith(OpenIdConnectAuthenticationDefaults.CookiePrefix + "nonce"));
               
               
                // if (oldNonces.Any())
               if (oldNonces.Count() > 2)
                {
                    System.Diagnostics.Trace.TraceInformation("Found excessive OpenId Authentication nonces.");

                    Microsoft.Owin.CookieOptions cookieOptions = new Microsoft.Owin.CookieOptions
                    {
                        HttpOnly = true,
                        Secure = Request.IsSecure
                    };
                    foreach (KeyValuePair<string, string> oldNonce in oldNonces)
                    {
                        Response.Cookies.Delete(oldNonce.Key, cookieOptions);
                    }
                }
                base.RememberNonce(message, nonce);
            }
        }
    }

}
