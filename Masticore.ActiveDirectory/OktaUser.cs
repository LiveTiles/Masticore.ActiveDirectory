using Masticore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Implements a current user around Okta
    /// Learn More: https://www.okta.com/
    /// Dev Docs: https://developer.okta.com/code/dotnet/aspnet/
    /// </summary>
    public class OktaUser : ICurrentUser
    {
        /// <summary>
        /// Gets true if the current user is authenticated; otherwise, returns false
        /// </summary>
        public virtual bool IsAuthenticated => HttpContext.Current.Request.IsAuthenticated;

        /// <summary>
        /// Gets the e-mail for the current userd
        /// </summary>
        public virtual string Email
        {
            get
            {
                var claim = ClaimsPrincipal.Current.FindFirst("email");
                return claim?.Value;
            }
        }

        /// <summary>
        /// Gets the subject (sub) for the current user
        /// </summary>
        public virtual string ExternalId
        {
            get
            {
                var claim = ClaimsPrincipal.Current.FindFirst("sub");
                if (claim == null)
                    throw new System.Exception("Current User Does Not Have a sub Claim");
                return claim.Value;
            }
        }

        /// <summary>
        /// Gets the first name (given name) for the current user
        /// </summary>
        public virtual string FirstName
        {
            get
            {
                var claim = ClaimsPrincipal.Current.FindFirst("given_name");
                return claim?.Value ?? "";
            }
        }

        /// <summary>
        /// Gets the last name (family name) for the current user
        /// </summary>
        public virtual string LastName
        {
            get
            {
                var claim = ClaimsPrincipal.Current.FindFirst("family_name");
                return claim?.Value ?? "";
            }
        }
    }
}
