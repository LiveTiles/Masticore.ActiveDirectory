# Masticore.ActiveDirectory
A library for integrating Azure Active Directory (Organization &amp; B2C) into an ASP.Net MVC Project.

This library is a refined version of the two boilerplate project configurations provided by Visual Studio 2015, intended to enable easy configuration via dependency injection and supporting various fixes to Azure AD's cookie management.
- A basic interface for describing signup, signin, and signout for applications
- An implementation of this interface for [Azure Active Directory](https://docs.microsoft.com/en-us/azure/active-directory/)
- An implementation of this interface for [Azure Active Directory B2C](https://docs.microsoft.com/en-us/azure/active-directory/)

When using this system, the developer need only:

1. Register with their DI system one of the implementations of IActiveDirectoryStrategy
2. Consume the IActiveDirectoryStrategy interface from the AccountController (or analogous controller) of their ASP.Net MVC project

Example AccountController
-------------------------------------
Find below an example AccountController exercising the basic functionality of IActiveDirectoryStrategy, using a constructor-based dependency injection framework and assuming all actions should simply redirect back to the root URL of the application:

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
