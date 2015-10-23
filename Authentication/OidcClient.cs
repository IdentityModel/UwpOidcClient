using IdentityModel;
using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Web.Http;

namespace Authentication
{
    public class OidcClient
    {
        private readonly string _authorizeEndpoint;
        private readonly string _identityTokenValidationEndpoint;
        private readonly string _endSessionEndpoint;

        private readonly string _clientId;
        private readonly string _scope;

        public OidcClient(string authority, string clientId, string scope)
        {
            _authorizeEndpoint = authority + "/connect/authorize";
            _identityTokenValidationEndpoint = authority + "/connect/identitytokenvalidation";
            _endSessionEndpoint = authority + "/connect/endsession";

            _clientId = clientId;
            _scope = scope;
        }

        public async Task<LoginResult> LoginAsync(bool trySilent = false)
        {
            var callback = WebAuthenticationBroker.GetCurrentApplicationCallbackUri();
            var nonce = Guid.NewGuid().ToString("N");

            var request = new AuthorizeRequest(_authorizeEndpoint);
            var url = request.CreateAuthorizeUrl(
                _clientId,
                "id_token token",
                _scope,
                callback.AbsoluteUri,
                nonce: nonce,
                responseMode: "form_post");

            WebAuthenticationResult result;

            // try silent mode if requested
            if (trySilent)
            {
                try
                {
                    result = await WebAuthenticationBroker.AuthenticateAsync(
                        WebAuthenticationOptions.SilentMode | WebAuthenticationOptions.UseHttpPost, new Uri(url));

                    if (result.ResponseStatus == WebAuthenticationStatus.Success)
                    {
                        return await ValidateAsync(result, nonce);
                    }
                }
                catch (Exception ex)
                {
                    return new LoginResult
                    {
                        Success = false,
                        Error = ex.Message
                    };
                }
            }

            // fall back to interactive mode
            try
            {
                result = await WebAuthenticationBroker.AuthenticateAsync(
                    WebAuthenticationOptions.UseHttpPost, new Uri(url));
            }
            catch (Exception ex)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }

            return await ValidateAsync(result, nonce);
        }

        public async Task LogoutAsync(string identityToken = null)
        {
            string url = _endSessionEndpoint;

            if (!string.IsNullOrWhiteSpace(identityToken))
            {
                url += "?id_token_hint=" + identityToken;
            }
            
            WebAuthenticationResult result;
            try
            {
                result = await WebAuthenticationBroker.AuthenticateAsync(
                    WebAuthenticationOptions.None, new Uri(url));
            }
            catch (Exception)
            { }
        }

        private async Task<LoginResult> ValidateAsync(WebAuthenticationResult result, string nonce)
        {
            // check broker response status code
            if (result.ResponseStatus != WebAuthenticationStatus.Success)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = result.ResponseStatus.ToString()
                };
            }

            // check oidc response message
            var response = new AuthorizeResponse(result.ResponseData);
            if (response.IsError)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = response.Error
                };
            }

            // validate identity token
            var principal = await ValidateIdentityTokenAsync(response.IdentityToken);
            if (principal == null)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "identity token validation error"
                };
            }

            // validate nonce
            var tokenNonce = principal.FindFirst("nonce")?.Value ?? "";
            if (!string.Equals(nonce, tokenNonce))
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "invalid nonce"
                };
            }

            // validate access token belongs to identity token
            var atHash = principal.FindFirst("at_hash")?.Value ?? "";
            var sha256 = HashAlgorithmProvider.OpenAlgorithm("SHA256");

            var tokenHash = sha256.HashData(
                CryptographicBuffer.CreateFromByteArray(
                    Encoding.ASCII.GetBytes(response.AccessToken)));

            byte[] tokenHashArray;
            CryptographicBuffer.CopyToByteArray(tokenHash, out tokenHashArray);

            byte[] leftPart = new byte[16];
            Array.Copy(tokenHashArray, leftPart, 16);

            var leftPartB64 = Base64Url.Encode(leftPart);

            if (!leftPartB64.Equals(atHash))
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "invalid access token"
                };
            }

            // success
            return new LoginResult
            {
                Success = true,
                Principal = principal,
                AccessToken = response.AccessToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(response.ExpiresIn),
                IdentityToken = response.IdentityToken,
                AuthenticationTime = DateTime.Now
            };
        }

        private async Task<ClaimsPrincipal> ValidateIdentityTokenAsync(string identityToken)
        {
            var client = new HttpClient();

            var form = new Dictionary<string, string>
            {
                { "token", identityToken },
                { "client_id", _clientId }
            };

            var response = await client.PostAsync(
                new Uri(_identityTokenValidationEndpoint),
                new HttpFormUrlEncodedContent(form));

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var json = JObject.Parse(await response.Content.ReadAsStringAsync());

            var claims = new List<Claim>();

            foreach (var x in json)
            {
                var array = x.Value as JArray;

                if (array != null)
                {
                    foreach (var item in array)
                    {
                        claims.Add(new Claim(x.Key, item.ToString()));
                    }
                }
                else
                {
                    claims.Add(new Claim(x.Key, x.Value.ToString()));
                }
            }

            return new ClaimsPrincipal(new ClaimsIdentity(claims, "OIDC"));
        }
    }
}