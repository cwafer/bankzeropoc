# Bank Zero Proof of Concept using Auth0 Identity Solutions
This proof of concept demonstrates several features of the Auth0 platform, including:
- Users can sign up and their username / password will be stored in the Auth0 DB
- Users who previously signed up can authenticate with username/password
- The Auth0 Lock sign-in screen has been customized to align with the bank's brand
- Users can also log in via Google and Microsoft social providers
- There is a whitelist rule applied such that only users with email domains of `bankzeropoc.com`, `gmail.com`, or `outlook.com` can login to the application.
- RBAC is used to set up two roles: `Manager` and `Employee`. These roles grant users different permissions: Managers can view a Manager Dashboard, while Employees can only view their own Profile. Roles are checked via the Management API.
- MFA is active for one of the Microsoft social connection users

## Requirements
* .[NET Core 2.1 SDK](https://www.microsoft.com/net/download/core)

## Auth0 Dashboard configuration settings
You may want to make some configuration changes via your Auth0 dashboard. 

1. This PoC uses Role Based Access Control (RBAC) and the roles "Manager" and "Employee". You can create these roles through Users & Roles->Roles and assign these roles to users through Users & Roles->Users. 

2. This PoC demonstrates Social connections with Google and Microsoft. You can enable these connections through Connections->Social.

3. Another feature the PoC demonstrates, but which operates outside of this .NET code, is domain whitelisting. The following Rule can be added through your Dashboard to achieve this in your environment:
```
function (user, context, callback) {
    var whitelist = ['bankzeropoc.com', 'gmail.com', 'outlook.com']; //authorized domains
    var userHasAccess = whitelist.some(
      function (domain) {
        var emailSplit = user.email.split('@');
        return emailSplit[emailSplit.length - 1].toLowerCase() === domain;
      });

    if (!userHasAccess) {
      //return callback(new UnauthorizedError('Access denied.'));
      return callback('Access denied');
    }

    return callback(null, user, context);
}
```

4. To apply custom branding to your Application, use Application->Click on your application->Application Logo, and Universal Login->Settings. The branding chosen for this PoC includes 
   - Application Logo: https://m5r5za.bl.files.1drv.com/y4mVfoSAgpbRn9s9OMH-lZk1CEhbHhZk7t_SSc0KjmrszTCvMj0SxOlRfEivNRuAv06LOGKSySlTV0JovYFLFYStHu_UQ79mnr7xaY8hXSEGVpUCpMxbX8E7JhgkUn_TY38SSl9VrcBRpE-plLkRYMpt1Dxgxl1iGNP3lA1_pBGkgLihTMA6EkZbIptjCXR0_Ni
   - Company Logo: https://m5r5za.bl.files.1drv.com/y4mVfoSAgpbRn9s9OMH-lZk1CEhbHhZk7t_SSc0KjmrszTCvMj0SxOlRfEivNRuAv06LOGKSySlTV0JovYFLFYStHu_UQ79mnr7xaY8hXSEGVpUCpMxbX8E7JhgkUn_TY38SSl9VrcBRpE-plLkRYMpt1Dxgxl1iGNP3lA1_pBGkgLihTMA6EkZbIptjCXR0_Ni, 
   - Primary Color: #eb5424
   - Page Background Color: #18603c

5. If you get access denied when trying to use the management API check that your Management API token has not changed. You can modify the TTL and generate a new token if needed. Dashboard->APIs->Auth0 Management API->API Explorer->Token and Token Expiration fields.

6. To support MFA with a Microsoft Account you will need to use your own application keys for the Microsoft Social Connection: [Add Microsoft Account Login to Your App](https://auth0.com/docs/connections/social/microsoft-account).

## Links to Relevant Quickstarts and other documentation
- [Getting Started with Auth0](https://auth0.com/docs/getting-started)
- [ASP.NET Core v2.1: Login](https://auth0.com/docs/quickstart/webapp/aspnet-core)
- [ASP.NET Core v2.1: User Profile](https://auth0.com/docs/quickstart/webapp/aspnet-core/02-user-profile)
- [ASP.NET Core v2.1: Authorization](https://auth0.com/docs/quickstart/webapp/aspnet-core/03-authorization)
- [Auth0 Management API](https://auth0.com/docs/api/management/v2)
- [Auth0 Authorization Code Flow](https://auth0.com/docs/flows/concepts/auth-code)


## To run this project

1. Ensure that you have replaced the [appsettings.json](appsettings.json) file with the values for your Auth0 account. Note that the "ManagementApiAccessToken" will by default change every 24 hours.

2. Run the application from the command line:

    ```bash
    dotnet run
    ```

3. Go to `http://localhost:3000` in your web browser to view the website.

## To run this project with docker

In order to run the example with docker you need to have **Docker** installed.

Execute in command line `sh exec.sh` to run the Docker in Linux or macOS, or `.\exec.ps1` to run the Docker in Windows.


## Important Snippets

### 1. Register the Cookie and OIDC Authentication handlers

```csharp
// Startup.cs

public void ConfigureServices(IServiceCollection services)
{
	// Add authentication services
    services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect("Auth0", options =>
    {
        // Set the authority to your Auth0 domain
        options.Authority = $"https://{Configuration["Auth0:Domain"]}";

        // Configure the Auth0 Client ID and Client Secret
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];

        // Set response type to code
        options.ResponseType = "code";

        // Configure the scope
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");

        // Set the callback path, so Auth0 will call back to http://localhost:3000/callback
        // Also ensure that you have added the URL as an Allowed Callback URL in your Auth0 dashboard
        options.CallbackPath = new PathString("/callback");

        // Configure the Claims Issuer to be Auth0
        options.ClaimsIssuer = "Auth0";

        // Set the correct name claim type
        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "name"
        };
```

### 2. Handle logins from non-whitelisted domains (if you implement the domain whitelisting rule)

```csharp
// Startup.cs

public void ConfigureServices(IServiceCollection services)
{
	// Code omitted for brevity
	// Handle error thrown by whitelisting domains...if a user logs in from a domain not in the whitelist it was throwing an unhandled exception
    // For purposes of the PoC we're just re-directing to the main page; 
    //      for production code you'd want to show the user an error message along the lines of "this e-mail domain is not supported".
    OnRemoteFailure = context =>
    {
        var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";

        context.Response.Redirect(logoutUri);
        context.HandleResponse();

        return Task.CompletedTask;
    }
```

### 3. Register the Authentication middleware

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
    }

    app.UseStaticFiles();

    // Register the Authentication middleware
    app.UseAuthentication();

    app.UseMvc(routes =>
    {
        routes.MapRoute(
            name: "default",
            template: "{controller=Home}/{action=Index}/{id?}");
    });
}
```

### 4. Challenge the OIDC middleware to log the user in

To log the user in, simply challenge the OIDC middleware. This will redirect to Auth0 to authenticate the user.

```csharp
// Controllers/AccountController.cs

public IActionResult Login(string returnUrl = "/")
{
    await HttpContext.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = returnUrl });
}
```

### 5. Log the user out

To log the user out, call the `SignOutAsync` method for both the OIDC middleware as well as the Cookie middleware.

```csharp
// Controllers/AccountController.cs

[Authorize]
public async Task Logout()
{
    await HttpContext.SignOutAsync("Auth0", new AuthenticationProperties
    {
        // Indicate here where Auth0 should redirect the user after a logout.
        // Note that the resulting absolute Uri must be whitelisted in the
        // **Allowed Logout URLs** settings for the client.
        RedirectUri = Url.Action("Index", "Home")
    });
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
}
```

When configuring the OIDC middleware, you will have to handle the `OnRedirectToIdentityProviderForSignOut` event to redirect
the user to the [Auth0 logout endpoint](https://auth0.com/docs/logout#log-out-a-user):

```csharp
services.AddAuthentication(options => {
    // Code omitted for brevity
})
.AddCookie()
.AddOpenIdConnect("Auth0", options => {
    // Code omitted for brevity

    options.Events = new OpenIdConnectEvents
    {
        // handle the logout redirection
        OnRedirectToIdentityProviderForSignOut = (context) =>
        {
            var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";

            var postLogoutUri = context.Properties.RedirectUri;
            if (!string.IsNullOrEmpty(postLogoutUri))
            {
                if (postLogoutUri.StartsWith("/"))
                {
                    // transform to absolute
                    var request = context.Request;
                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                }
                logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
            }

            context.Response.Redirect(logoutUri);
            context.HandleResponse();

            return Task.CompletedTask;
        }
    };
});
```

### 6. Relevant Views
`HomeController.cs` and `AccountController.cs` build the `ManagerDashboardViewModel` and `UserProfileViewModel`. 

### 7. Management API Helper Class
`ManagementApiHelper.cs` contains functions for querying the Management API for user information, including User ID and assigned Roles. This PoC supports users assigned to a single role, but you can modify the code to iterate over multiple roles if you'd like. [Management API documentation](https://auth0.com/docs/api/management/v2).

## Passing additional parameters to the /authorize endpoint

When asking Auth0 to authenticate a user, you might want to provide additional parameters to the `/authorize` endpoint, such as the `connection`, `offline_access`, `audience` or others. In order to do so, you need to handle the `OnRedirectToIdentityProvider` event when configuring the `OpenIdConnectionOptions` and call the `ProtocolMessage.SetParameter` method on the supplied `RedirectContext`:

```csharp
// Add the OIDC middleware
services.AddAuthentication(options => {
    // Code omitted for brevity
})
.AddCookie()
.AddOpenIdConnect("Auth0", options => {
    // Code omitted for brevity

    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            // add any custom parameters here
            context.ProtocolMessage.SetParameter("connection", "google-oauth2");

            return Task.CompletedTask;
        }
    };
});
```

If you need to make this dynamic (i.e. provide information that affects what parameters will be set), take a look at [this blog post](http://www.jerriepelser.com/blog/adding-parameters-to-openid-connect-authorization-url/).
