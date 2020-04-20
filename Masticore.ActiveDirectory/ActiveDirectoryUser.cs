using System.Security.Claims;
using System.Web;

namespace Masticore.Mvc
{
    /// <inheritdoc />
    /// <summary>
    /// Implementation of ICurrentUser provided via Active Directory
    /// </summary>
    public class ActiveDirectoryUser : ICurrentUser
    {
        /// <summary>
        /// The URI for the object identifier claim type
        /// </summary>
        public const string ObjectIdentifierClaimType = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        /// <summary>
        /// The URI for the object identifier claim type using newer JWT format
        /// </summary>
        public const string OidClaimType = "oid";

        /// <summary>
        /// The URI for the emails claim type
        /// </summary>
        public const string EmailClaimType = "emails";
        /// <summary>
        /// The URI for the newer JWT claim type for email/upn
        /// </summary>
        /// 
        public const string UpnClaimType = "upn";
        /// <summary>
        /// Gets true if the current user is authenticated; otherwise, returns false
        /// </summary>
        public virtual bool IsAuthenticated => HttpContext.Current.Request.IsAuthenticated;

        /// <summary>
        /// Gets the e-mail for the current user - returns the current Identity Name as a best-guess if the claim is not found
        /// </summary>
        public virtual string Email
        {
            get
            {
               
                var claim = ClaimsPrincipal.Current.FindFirst(EmailClaimType);
                if (claim == null)
                {
                    claim = ClaimsPrincipal.Current.FindFirst(UpnClaimType);
                }
                return claim?.Value ?? ClaimsPrincipal.Current.Identity.Name;
            }
        }

        /// <summary>
        /// Gets the unique identifier (OID) for the current user
        /// </summary>
        public virtual string ExternalId
        {
            get
            {
                var claim = ClaimsPrincipal.Current.FindFirst(ObjectIdentifierClaimType);
                if (claim == null)
                {
                    //Try the new oid format
                    claim = ClaimsPrincipal.Current.FindFirst(OidClaimType);
                    if (claim == null)
                        throw new System.Exception("Current User Does Not Have an Object Identifier Claim");
                }
         
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
                var claim = ClaimsPrincipal.Current.FindFirst(ClaimTypes.GivenName);
                return claim?.Value ?? "";
            }
        }

        /// <summary>
        /// Gets the last name (surname) for the current user
        /// </summary>
        public virtual string LastName
        {
            get
            {
                var claim = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Surname);
                return claim?.Value ?? "";
            }
        }
    }
}
