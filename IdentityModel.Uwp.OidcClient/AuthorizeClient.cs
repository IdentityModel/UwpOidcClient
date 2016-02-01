// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using System;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace IdentityModel.Uwp.OidcClient
{
    public class AuthorizeClient
    {
        private readonly OidcClientSettings _settings;

        public AuthorizeClient(OidcClientSettings settings)
        {
            _settings = settings;
        }

        public static string GetCallbackUrl()
        {
            return WebAuthenticationBroker.GetCurrentApplicationCallbackUri().AbsoluteUri;
        }

        public async Task<AuthorizeResult> StartAsync(bool trySilent = false)
        {
            WebAuthenticationResult wabResult;
            AuthorizeResult result = new AuthorizeResult
            {
                IsError = true,
            };

            result.Nonce = Guid.NewGuid().ToString("N");
            result.RedirectUri = WebAuthenticationBroker.GetCurrentApplicationCallbackUri().AbsoluteUri;
            string codeChallenge = CreateCodeChallenge(result);
            var url = CreateUrl(result, codeChallenge);
            
            // try silent mode if requested
            if (trySilent)
            {
                try
                {
                    var options = WebAuthenticationOptions.SilentMode | WebAuthenticationOptions.UseHttpPost;
                    if (_settings.EnableWindowsAuthentication)
                    {
                        options = options | WebAuthenticationOptions.UseCorporateNetwork;
                    }

                    wabResult = await WebAuthenticationBroker.AuthenticateAsync(
                        options, new Uri(url));

                    if (wabResult.ResponseStatus == WebAuthenticationStatus.Success)
                    {
                        return await ParseResult(wabResult, result);

                    }
                }
                catch (Exception ex)
                {
                    result.Error = ex.Message;
                    return result;
                }
            }

            // fall back to interactive mode
            try
            {
                var options = WebAuthenticationOptions.UseHttpPost;
                if (_settings.EnableWindowsAuthentication)
                {
                    options = options | WebAuthenticationOptions.UseCorporateNetwork;
                }

                wabResult = await WebAuthenticationBroker.AuthenticateAsync(
                    options, new Uri(url));
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                return result;
            }

            return await ParseResult(wabResult, result);
        }

        private string CreateUrl(AuthorizeResult result, string codeChallenge)
        {
            var request = new AuthorizeRequest(_settings.Endpoints.Authorize);
            var url = request.CreateAuthorizeUrl(
                clientId: _settings.ClientId,
                responseType: OidcConstants.ResponseTypes.CodeIdToken,
                scope: _settings.Scope,
                redirectUri: result.RedirectUri,
                responseMode: OidcConstants.ResponseModes.FormPost,
                nonce: result.Nonce,
                codeChallenge: codeChallenge,
                codeChallengeMethod: _settings.UseProofKeys ? OidcConstants.CodeChallengeMethods.Sha256 : null);

            return url;
        }

        private string CreateCodeChallenge(AuthorizeResult result)
        {
            if (_settings.UseProofKeys)
            {
                result.Verifier = Guid.NewGuid().ToString("N");
                var sha256 = HashAlgorithmProvider.OpenAlgorithm("SHA256");

                var challengeBuffer = sha256.HashData(
                    CryptographicBuffer.CreateFromByteArray(
                        Encoding.ASCII.GetBytes(result.Verifier)));
                byte[] challengeBytes;

                CryptographicBuffer.CopyToByteArray(challengeBuffer, out challengeBytes);
                return Base64Url.Encode(challengeBytes);
            }
            else
            {
                return null;
            }
        }

        private Task<AuthorizeResult> ParseResult(WebAuthenticationResult authenticationResult, AuthorizeResult result)
        {
            var response = new AuthorizeResponse(authenticationResult.ResponseData);

            if (response.IsError)
            {
                result.Error = response.Error;
                return Task.FromResult(result);
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                result.Error = "Missing authorization code";
                return Task.FromResult(result);
            }

            if (string.IsNullOrEmpty(response.IdentityToken))
            {
                result.Error = "Missing identity token";
                return Task.FromResult(result);
            }

            result.IdentityToken = response.IdentityToken;
            result.Code = response.Code;
            result.IsError = false;

            return Task.FromResult(result);
        }
    }
}