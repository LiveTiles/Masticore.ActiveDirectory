using Owin;
using System.Web.Mvc;

namespace Masticore.ActiveDirectory
{
    /// <summary>
    /// Interface for an object that implements a strategy for Active Directory Integration
    /// </summary>
    public interface IActiveDirectoryStrategy
    {
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
    }
}