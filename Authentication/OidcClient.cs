﻿using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.Web.Http;

namespace Authentication
{
    public class OidcClient
    {
        private readonly AuthorizeClient _authorizeClient;
        private readonly OidcSettings _settings;

        public OidcClient(OidcSettings settings)
        {
            _authorizeClient = new AuthorizeClient(settings);
            _settings = settings;
        }

        public async Task<LoginResult> LoginAsync(bool trySilent = false)
        {
            var authorizeResult = await _authorizeClient.StartAsync(trySilent);

            if (authorizeResult.IsError)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = authorizeResult.Error
                };
            }

            return await ValidateAsync(authorizeResult);
        }

        public async Task LogoutAsync(string identityToken = null)
        {
            string url = _settings.Endpoints.EndSession;

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

        private async Task<LoginResult> ValidateAsync(AuthorizeResult result)
        {
            // validate identity token
            var principal = await ValidateIdentityTokenAsync(result.IdentityToken);
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
            if (!string.Equals(result.Nonce, tokenNonce))
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "invalid nonce"
                };
            }

            // validate audience
            var audience = principal.FindFirst("aud")?.Value ?? "";
            if (!string.Equals(_settings.ClientId, audience))
            {
                return new LoginResult
                {
                    Success = false,
                    Error = "invalid audience"
                };
            }

            // validate access token belongs to identity token
            //var atHash = principal.FindFirst("at_hash")?.Value ?? "";
            //var sha256 = HashAlgorithmProvider.OpenAlgorithm("SHA256");

            //var tokenHash = sha256.HashData(
            //    CryptographicBuffer.CreateFromByteArray(
            //        Encoding.ASCII.GetBytes(result.AccessToken)));

            //byte[] tokenHashArray;
            //CryptographicBuffer.CopyToByteArray(tokenHash, out tokenHashArray);

            //byte[] leftPart = new byte[16];
            //Array.Copy(tokenHashArray, leftPart, 16);

            //var leftPartB64 = Base64Url.Encode(leftPart);

            //if (!leftPartB64.Equals(atHash))
            //{
            //    return new LoginResult
            //    {
            //        Success = false,
            //        Error = "invalid access token"
            //    };
            //}

            // success
            return new LoginResult
            {
                Success = true,
                Principal = principal,
                AccessToken = result.AccessToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(result.ExpiresIn),
                IdentityToken = result.IdentityToken,
                AuthenticationTime = DateTime.Now
            };
        }

        private async Task<ClaimsPrincipal> ValidateIdentityTokenAsync(string identityToken)
        {
            var client = new HttpClient();

            var form = new Dictionary<string, string>
            {
                { "token", identityToken },
                { "client_id", _settings.ClientId }
            };

            var response = await client.PostAsync(
                new Uri(_settings.Endpoints.IdentityTokenValidation),
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