using Masticore.Infrastructure.Azure;
using System.Collections.Generic;
using System.Linq;
using System.Data.Entity;


namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Static class used to store tenant level mapping of active directory setting, for use across web apps
    /// </summary>
    public static class AuthenticationPolicy
    {
        private static Dictionary<string, ActiveDirectorySettings> _authentication = new Dictionary<string, ActiveDirectorySettings>();
        /// <summary>
        /// Class to store shareable settings
        /// </summary>
        public class ActiveDirectorySettings
        {
            public string ProfilePolicy { get; set; }
            public string RedirectUrl { get; set; }
            public string SignInPolicy { get; set; }
            public string SignUpPolicy { get; set; }
        }
        /// <summary>
        /// Gets or sets cached custom aliased active directory settings
        /// </summary>
        /// <param name="host">The authority for the mapping</param>
        /// <returns></returns>
        public static ActiveDirectorySettings GetAuthenticationPolicyInfo(string host)
        {
            if (_authentication.ContainsKey(host))
                return _authentication[host];

            ActiveDirectorySettings authenticationSettings = null;
            using (var db = new AzureInfrastructureDbContext())
            {
                host = host.ToLower();
                var alias = db.TenantAlias.Where(ta => ta.Name.ToLower() == host).Include(ta => ta.Tenant).FirstOrDefault();
                if (alias != null)
                {
                    authenticationSettings = new ActiveDirectorySettings() { ProfilePolicy = alias.ProfilePolicy, RedirectUrl = alias.RedirectUrl, SignInPolicy = alias.SigninPolicy, SignUpPolicy = alias.SignupPolicy };

                }
            }
            if (authenticationSettings != null)
                _authentication[host] = authenticationSettings;

            return authenticationSettings;
        }
    }
}
