using BankZeroIDPoC.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using System.IO;
using Microsoft.Extensions.Configuration;

namespace BankZeroIDPoC.Controllers
{
    public class AccountController : Controller
    {
        public async Task Login(string returnUrl = "/")
        {
            await HttpContext.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = returnUrl });
        }

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

        /// <summary>
        /// This is just a helper action to enable you to easily see all claims related to a user. It helps when debugging your
        /// application to see the in claims populated from the Auth0 ID Token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Claims()
        {
            return View();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        /// <summary>
        /// Extract the relevant user claims and add them to the UserProfileViewModel passed to the view
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Profile()
        {
            string apiUrl, accessToken, userEmail, userId, userRole, userPermissions;
            
            // Get the configuration information to access the Management API
            var config = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json").Build();
            apiUrl = "https://" + config["Auth0:Domain"] + "/api/v2/";
            accessToken = config["Auth0:ManagementApiAccessToken"];

            ManagementApiHelper managementApi = new ManagementApiHelper();

            // Get the user ID
            userEmail = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;            
            userId = managementApi.GetUserId(userEmail, apiUrl, accessToken);

            // Get the roles            
            userRole = managementApi.GetUserRole(userId, apiUrl, accessToken);

            // Get the permissions - for this PoC we're just asking for the raw JSON to display on the Profile.
            userPermissions = managementApi.GetUserPermissions(userId, apiUrl, accessToken);

            // Insert newlines between the permissions and spaces between the fields since we're displaying raw JSON
            userPermissions = userPermissions.Replace("}]},", "}]},<p/>");
            userPermissions = userPermissions.Replace("\",\"", "\", \"");

            // Build the view
            // Note that for the sake of this POC we're supporting the display of one role per user. For multiple roles you'd iterate/build a string/table/etc.
            return View(new UserProfileViewModel()
            {
                Name = User.Identity.Name,
                EmailAddress = userEmail,
                ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value,
                Roles = userRole,
                Permissions = userPermissions
            });
        }
    }
}
