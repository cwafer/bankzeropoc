using Newtonsoft.Json.Linq;
using System.IO;
using System.Net;

namespace BankZeroIDPoC
{
    /// <summary>
    /// This class provides helper functions to access the Auth0 Management API
    /// </summary>
    public class ManagementApiHelper
    {
        /// <summary>
        /// Get the UserId for a user based on their e-mail. Most user-related functions of the Management API take UserId instead of e-mail address.
        /// </summary>
        /// <param name="userEmail">The e-mail address of the user.</param>
        /// <param name="apiUrl">The base URL to the Management API.</param>
        /// <param name="accessToken">The access token for the Management API.</param>
        /// <returns></returns>
        public string GetUserId(string userEmail, string apiUrl, string accessToken)
        {
            string userJson;

            try
            {                
                userJson = GetJsonFromManagementApi(apiUrl + "users-by-email?email=" + userEmail, accessToken);

                return GetJsonValue(userJson, "user_id");
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// Get the roles for the user. For this PoC we're supporting one role per user, but if you'd like users to have multiple roles you could 
        /// iterate over the result and return something like an array.
        /// </summary>
        /// <param name="userId">The userId of the user. If you just have their e-mail address call GetUserId first.</param>
        /// <param name="apiUrl">The base URL to the Management API.</param>
        /// <param name="accessToken">The access token for the management API.</param>
        /// <returns>The role of the user.</returns>
        public string GetUserRole(string userId, string apiUrl, string accessToken)
        {
            string userJson, userRole;

            try
            {
                userJson = GetJsonFromManagementApi(apiUrl + "users/" + userId + "/roles", accessToken);

                userRole = GetJsonValue(userJson, "name");
            }
            catch
            {
                userRole = "";
            }

            if (userRole == "")
            {
                userRole = "You do not have a role set for your account. Please contact the Bank Zero helpdesk.";
            }

            return userRole;
        }

        /// <summary>
        /// Get the permissions set for the user. Note for this PoC we're just returning the raw JSON to show that on the page
        /// </summary>
        /// <param name="userId">The userId of the user. If you just have their e-mail address call GetUserId first.</param>
        /// <param name="apiUrl">The base URL to the Management API.</param>
        /// <param name="accessToken">The access token for the management API.</param>
        /// <returns>Permissions for the user.</returns>
        public string GetUserPermissions(string userId, string apiUrl, string accessToken)
        {
            string userJson, userPermissions;

            try
            {
                userJson = GetJsonFromManagementApi(apiUrl + "users/" + userId + "/permissions", accessToken);
            }
            catch
            {
                userJson = "";
            }
            
            userPermissions = userJson;

            if (userPermissions == "[]")
            {
                userPermissions = "You currently have no permissions set for your account. Please contact the Bank Zero helpdesk.";
            }

            return userPermissions;            
        }

        /// <summary>
        /// Private helper function to call the Management API and return the JSON result.
        /// </summary>
        /// <param name="requestUri">URI for the Management API endpoint.</param>
        /// <param name="accessToken">The access token for the management API.</param>
        /// <returns>JSON result as a string.</returns>
        private string GetJsonFromManagementApi(string requestUri, string accessToken)
        {
            string responseStream;

            HttpWebRequest apiRequest = (HttpWebRequest)HttpWebRequest.Create(requestUri);
            apiRequest.Headers["Authorization"] = accessToken;
            apiRequest.ContentType = "application/json";
            apiRequest.Method = "GET";

            var httpResponse = (HttpWebResponse)apiRequest.GetResponse();
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                responseStream = streamReader.ReadToEnd();
            }

            return responseStream;
        }

        /// <summary>
        /// Private helper function to retrieve the value of a key in a JSON string.
        /// </summary>
        /// <param name="jsonString">The input JSON string.</param>
        /// <param name="key">The key to retrieve the value for.</param>
        /// <returns>The value of the requested key.</returns>
        private string GetJsonValue(string jsonString, string key)
        {
            // Need to trim leading and trailing brackets for the parser to work since the Management API is returning a format that JObject doesn't like.
            jsonString = jsonString.TrimStart(new char[] { '[' }).TrimEnd(new char[] { ']' });

            // Parse the JSON reply
            try
            {
                JObject details = JObject.Parse(jsonString);

                // Return the requested key value
                return details[key].ToString();
            }
            catch { return ""; }
        }        
    }
}
