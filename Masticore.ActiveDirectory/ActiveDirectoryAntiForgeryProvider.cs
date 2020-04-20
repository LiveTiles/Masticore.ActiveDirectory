using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;

namespace Masticore.ActiveDirectory
{
    public class ActiveDirectoryAntiForgeryProvider : IAntiForgeryAdditionalDataProvider
    {
        private readonly string ClaimTypeV2 = "oid";
        private readonly string ClaimTypeV1 = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        public string GetAdditionalData(HttpContextBase context)
        {
            return getClaim();
        }

        public bool ValidateAdditionalData(HttpContextBase context, string additionalData)
        {
            return additionalData == getClaim();
        }

        private string getClaim()
        {
            return ClaimsPrincipal.Current.FindFirst(ClaimTypeV2)?.Value ?? ClaimsPrincipal.Current.FindFirst(ClaimTypeV1)?.Value;
        }
    }

}
