using Owin;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Interface for an object that implements a strategy for Active Directory Integration
    /// </summary>
    public interface IAuthStrategy
    {
        string RedirectUrl { get; set; }
        string PostLogoutUrl { get; set; }
        string ClientId { get; set; }
        string ClientSecret { get; set; }

        string SignInPolicyId { get; set; }
        string SignUpPolicyId { get; set; }
        string ProfilePolicyId { get; set; }
        string Domain { get; set; }

        /// <summary>
        /// Configures the app on initial load
        /// </summary>
        /// <param name="app"></param>
        void Configure(IAppBuilder app);

        /// <summary>
        /// Called to register the current user with the current strategy
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        void SignUp(Controller controller, string redirectUri);

        /// <summary>
        /// Called to login the current user with the current strategy
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        void SignIn(Controller controller, string redirectUri);

        /// <summary>
        /// Called to logout the current user with the current strategy
        /// </summary>
        /// <param name="controller"></param>
        /// <param name="redirectUri"></param>
        void SignOut(Controller controller, string redirectUri);


        /// <summary>
        /// Load the access token from Authentication Strategy
        /// </summary>
        /// <returns>A string with the access token, if available</returns>
        Task<string> GetAuthenticationTokenAsync();
    }
}
