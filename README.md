# Masticore.ActiveDirectory
A library for integrating Azure Active Directory (Organization &amp; B2C) into an ASP.Net MVC Project.

Installation
-------------------------------------
To use Masticore.ActiveDirectory, either download the code using git, build the "Masticore.ActiveDirectory" project, and include an assembly reference in your project to the "Masticore.ActiveDirectory.dll" assembly.

OR

Install the package from NuGet (https://www.nuget.org/packages/Masticore.ActiveDirectory/) using the following command in the package manager console in Visual Studio:

```
Install-Package Masticore.ActiveDirectory
```

Summary
-------------------------------------

This library is a refined version of the two boilerplate project configurations provided by Visual Studio 2015, intended to enable easy configuration via dependency injection and supporting various fixes to Azure AD's cookie management.
- A basic interface for describing signup, signin, and signout for applications
- An implementation of this interface for [Azure Active Directory](https://docs.microsoft.com/en-us/azure/active-directory/), the style used for Work/School accounts (EG, Office 365)
- An implementation of this interface for [Azure Active Directory B2C](https://docs.microsoft.com/en-us/azure/active-directory/)

When using this system, the developer need only:

1. Register with their DI system one of the implementations of IActiveDirectoryStrategy
2. Consume the IActiveDirectoryStrategy interface from the AccountController (or analogous controller) of their ASP.Net MVC project
3. Provide a configuration for the chosen strategy in your web.config file

Example AccountController
-------------------------------------
Find below an example AccountController exercising the basic functionality of IActiveDirectoryStrategy, using a constructor-based dependency injection framework and assuming all actions should simply redirect back to the root URL of the application. This class should work for either strategy:

```
public class AccountController : Controller
{
    IActiveDirectoryStrategy _activeDirectoryStrategy;

    public AccountController(IActiveDirectoryStrategy activeDirectoryStrategy)
    {
        _activeDirectoryStrategy = activeDirectoryStrategy;
    }

    public void SignUp()
    {
        _activeDirectoryStrategy.SignUp(this, "/");
    }

    public void SignIn()
    {
        _activeDirectoryStrategy.SignIn(this, "/");
    }

    public void SignOut()
    {
        _activeDirectoryStrategy.SignOut(this, "/");
    }
}
```

Example Configuration in Web.Config
-------------------------------------
The exact style of web.config depends on your chosen strategy. Original AD is the simplest:

```
<!-- AD B2C Configuration -->
<add key="ida:AadInstance" value="https://login.microsoftonline.com/" />
<add key="ida:ClientId" value="[YourAppGuidFromPortal]" />
```

B2C requires dramatically more information to work correctly. Example B2C Configuration:
```
<!-- AD B2C Configuration -->
<add key="ida:RedirectUri" value="https://localhost:44343/" />
<add key="ida:AadInstance" value="https://login.microsoftonline.com/" />
<!-- QA AD Settings -->
<add key="ida:Domain" value="[YourAdName].onmicrosoft.com" />
<add key="ida:ClientId" value="[YourAppGuidFromPortal]" />
<add key="ida:SignUpPolicyId" value="B2C_1_ltc-teams-signup-policy" />
<add key="ida:SignInPolicyId" value="B2C_1_ltc-teams-signin" />
<add key="ida:UserProfilePolicyId" value="B2C_1_ltc-teams-profile" />
```
