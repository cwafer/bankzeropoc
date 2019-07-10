using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BankZeroIDPoC.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace BankZeroIDPoC.Controllers
{
    public class HomeController : Controller
    {
        //[Authorize(Roles = "manager")] <-- This is how you would restrict access to code paths based on Role
        public async Task<IActionResult> Index()
        {
            // If the user is authenticated, then this is how you can get the access_token and id_token
            if (User.Identity.IsAuthenticated)
            {
                string accessToken = await HttpContext.GetTokenAsync("access_token");

                // if you need to check the access token expiration time, use this value
                // provided on the authorization response and stored.
                // do not attempt to inspect/decode the access token
                DateTime accessTokenExpiresAt = DateTime.Parse(
                    await HttpContext.GetTokenAsync("expires_at"),
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind);

                string idToken = await HttpContext.GetTokenAsync("id_token");

                // Now you can use them. For more info on when and how to use the
                // access_token and id_token, see https://auth0.com/docs/tokens
            }

            return View();
        }

        /// <summary>
        /// Extract the relevant user claims and add them to the ManagerDashboardViewModel passed to the view
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Manager()
        {
            string apiUrl, accessToken, userEmail, userId, userRole;
            string teamMembers, expenseReports, unauthorizedMessage;

            unauthorizedMessage = "Sorry, you must be a manager to see this information.";

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

            // For purposes of the POC we're going to hard-code some data for the manager dashboard. In actual use, the app would get this data from a DB or other directory
            if (userRole.ToLower() == "manager")
            { 
                teamMembers = "Bob, Priya, Jack, Samantha";
                expenseReports = "Link to expense report application";
            }
            else
            {                
                teamMembers = unauthorizedMessage;
                expenseReports = unauthorizedMessage;
            }

            // Build the view
            return View(new ManagerDashboardViewModel()
            {
                Name = User.Identity.Name,
                EmailAddress = userEmail,
                ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value,
                TeamMembers = teamMembers,
                ExpenseReports = expenseReports,
                Roles = userRole
            });
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}
