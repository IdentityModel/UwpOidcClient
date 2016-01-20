using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace Authentication
{
    public class OidcSettings
    {
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; set; }

        public Endpoints Endpoints { get; set; } = new Endpoints();

        public OidcSettings(string clientId, string clientSecret, string scope)
        {
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));
            if (string.IsNullOrWhiteSpace(scope)) throw new ArgumentNullException(nameof(scope));

            ClientId = clientId;
            ClientSecret = clientSecret;
            Scope = scope;
        }

        public async Task LoadEndpointsFromMetadataAsync(string authority)
        {
            var client = new HttpClient();
            var url = authority.EnsureTrailingSlash() + ".well-known/openid-configuration";

            var json = await client.GetStringAsync(url);

            var doc = (IDictionary<string, object>)SimpleJson.SimpleJson.DeserializeObject(json);

            Endpoints = new Endpoints
            {
                Authorize = doc["authorization_endpoint"].ToString(),
                Token = doc["token_endpoint"].ToString(),
                EndSession = doc["end_session_endpoint"].ToString(),
            };

            // todo: replace with local validation
            Endpoints.IdentityTokenValidation = authority.EnsureTrailingSlash() + "connect/identitytokenvalidation";
        }
    }

    public class Endpoints
    {
        public string Token { get; set; }
        public string Authorize { get; set; }
        public string IdentityTokenValidation { get; set; }
        public string EndSession { get; set; }
    }
}