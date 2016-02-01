// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.Web.Http;

namespace IdentityModel.Uwp.OidcClient
{
    public class OidcClient
    {
        private readonly AuthorizeClient _authorizeClient;
        private readonly OidcClientSettings _settings;

        public OidcClient(OidcClientSettings settings)
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

        public async Task LogoutAsync(string identityToken = null, bool trySilent = true)
        {
            string url = _settings.Endpoints.EndSession;

            if (!string.IsNullOrWhiteSpace(identityToken))
            {
                url += "?id_token_hint=" + identityToken;
            }

            WebAuthenticationResult result;
            try
            {
                if (trySilent)
                {
                    result = await WebAuthenticationBroker.AuthenticateAsync(
                        WebAuthenticationOptions.SilentMode, new Uri(url));

                    if (result.ResponseStatus == WebAuthenticationStatus.Success)
                    {
                        return;
                    }
                }

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

            // validate c_hash

            // get access token
            var tokenClient = new TokenClient(_settings.Endpoints.Token, _settings.ClientId, _settings.ClientSecret);
            var tokenResult = await tokenClient.RequestAuthorizationCodeAsync(result.Code, result.RedirectUri);

            if (tokenResult.IsError || tokenResult.IsHttpError)
            {
                return new LoginResult
                {
                    Success = false,
                    Error = tokenResult.Error
                };
            }

            // get profile if enabled
            if (_settings.LoadProfile)
            {
                var userInfoClient = new UserInfoClient(new Uri(_settings.Endpoints.UserInfo), tokenResult.AccessToken);
                var userInfoResponse = await userInfoClient.GetAsync();

                var primaryClaimTypes = principal.Claims.Select(c => c.Type).Distinct();

                foreach (var claim in userInfoResponse.Claims.Where(c => !primaryClaimTypes.Contains(c.Item1)))
                {
                    principal.Identities.First().AddClaim(new Claim(claim.Item1, claim.Item2));
                }

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
                Principal = FilterProtocolClaims(principal),
                AccessToken = tokenResult.AccessToken,
                AccessTokenExpiration = DateTime.Now.AddSeconds(tokenResult.ExpiresIn),
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

        private ClaimsPrincipal FilterProtocolClaims(ClaimsPrincipal principal)
        {
            if (_settings.FilterProtocolClaims)
            {
                var filteredClaims = principal.Claims.ToList().Where(c => !_settings.ProtocolClaims.Contains(c.Type));

                var id = new ClaimsIdentity(filteredClaims, principal.Identities.First().AuthenticationType);
                return new ClaimsPrincipal(id);
            }

            return principal;
        }
    }
}