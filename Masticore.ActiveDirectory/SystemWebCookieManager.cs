using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using System;
using System.Web;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Write Cookies directly to the System.Web cookie collection
    /// From http://katanaproject.codeplex.com/wikipage?title=System.Web%20response%20cookie%20integration%20issues&referringTitle=Documentation
    /// </summary>
    public class SystemWebCookieManager : ICookieManager
    {
        /// <summary>
        /// Get the cookies from the Request.
        /// </summary>
        /// <param name="context">The context for the Owin Environment</param>
        /// <param name="key">The key for accessing the cookie</param>
        /// <returns>The cookie value</returns>
        public string GetRequestCookie(IOwinContext context, string key)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            var webContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);
            var cookie = webContext.Request.Cookies[key];
            return cookie == null ? null : cookie.Value;
        }
        /// <summary>
        /// Append the cookie to the Response
        /// </summary>
        /// <param name="context">The context for the Owin Environment</param>
        /// <param name="key">The key for storing the cookie</param>
        /// <param name="value">The cookie value</param>
        /// <param name="options">The cookie options (e.g., secure, http only, domain, path)</param>
        public void AppendResponseCookie(IOwinContext context, string key, string value, CookieOptions options)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            var webContext = context.Get<HttpContextBase>(typeof(HttpContextBase).FullName);

            var domainHasValue = !string.IsNullOrEmpty(options.Domain);
            var pathHasValue = !string.IsNullOrEmpty(options.Path);
            var expiresHasValue = options.Expires.HasValue;

            var cookie = new HttpCookie(key, value);
            if (domainHasValue)
            {
                cookie.Domain = options.Domain;
            }
            if (pathHasValue)
            {
                cookie.Path = options.Path;
            }
            if (expiresHasValue)
            {
                cookie.Expires = options.Expires.Value;
            }
            if (options.Secure)
            {
                cookie.Secure = true;
            }
            if (options.HttpOnly)
            {
                cookie.HttpOnly = true;
            }

            webContext.Response.AppendCookie(cookie);
        }
        /// <summary>
        /// Deletes (expires) the given cookie
        /// </summary>
        /// <param name="context">The Owin environment</param>
        /// <param name="key">The key for the cookie</param>
        /// <param name="options">Any associated cookie options, (e.g., domain, path)</param>
        public void DeleteCookie(IOwinContext context, string key, CookieOptions options)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            AppendResponseCookie(
                context,
                key,
                string.Empty,
                new CookieOptions
                {
                    Path = options.Path,
                    Domain = options.Domain,
                    Expires = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                });
        }
    }

}
