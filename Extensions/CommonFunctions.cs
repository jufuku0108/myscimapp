using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Net.Http;
using IdentityModel.Client;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;

namespace MyScimApp.Extensions
{
    public static class CommonFunctions
    {
        private static HttpClient _httpClient = new HttpClient();

        public static async Task<string> GetAccessTokenFromStsAync(IConfiguration configuration)
        {

            var disco = await _httpClient.GetDiscoveryDocumentAsync(configuration["MyScimApp"]);
            var tokenResponse = await _httpClient.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = configuration["MyScimAppClientId"],
                ClientSecret = configuration["MyScimAppClientSecret"],
                Scope = "users.read.write"
            });
            return tokenResponse.AccessToken;
        }

        public static async Task<JObject> GetScimUserAync(IConfiguration configuration, string userName)
        {
            _httpClient.SetBearerToken(await GetAccessTokenFromStsAync(configuration));
            var endPoint = configuration["MyScimAPI"] + "/scim/v2/Users?filter=userName eq " + userName;
            var response = await _httpClient.GetAsync(endPoint);

            var content = await response.Content.ReadAsStringAsync();
            var jResponse = JObject.Parse(content);
            if ((int)jResponse["totalResults"] != 0)
            {
                jResponse.Add(new JProperty("success", true));
                return jResponse;
            }
            
            return new JObject(new JProperty("success", false));
        }
        public static async Task<JObject> ProvisionScimUserAync(IConfiguration configuration, string id, string userName)
        {
            _httpClient.SetBearerToken(await GetAccessTokenFromStsAync(configuration));

            var jRequest = new JObject();
            var jSchemas = new JArray();
            jSchemas.Add("urn:ietf:params:scim:schemas:core:2.0:User");
            jRequest.Add(new JProperty("id", id));
            jRequest.Add(new JProperty("schemas", jSchemas));
            jRequest.Add(new JProperty("userName", userName));
            jRequest.Add(new JProperty("externalId", id));
            var request = new StringContent(jRequest.ToString(), Encoding.UTF8, "application/json");
            var createResult = _httpClient.PostAsync(configuration["MyScimAPI"] + "/scim/v2/Users", request).Result;
            if (createResult.StatusCode == System.Net.HttpStatusCode.Created)
            {
                var content = await createResult.Content.ReadAsStringAsync();
                var jResponse = JObject.Parse(content);
                
                jResponse.Add(new JProperty("success", true));
                return jResponse;
            }

            return new JObject(new JProperty("success", false));
        }

        public static string FormatException(Exception exception)
        {
            return string.Format("{0}{1}", exception.Message, exception.InnerException != null ? "(" + exception.InnerException + ")" : "");
        }

    }

}
