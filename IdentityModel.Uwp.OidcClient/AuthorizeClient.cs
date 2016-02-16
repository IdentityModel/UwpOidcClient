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
        private readonly OidcClientOptions _options;

        public AuthorizeClient(OidcClientOptions options)
        {
            _options = options;
        }

        public static string GetCallbackUrl()
        {
            return WebAuthenticationBroker.GetCurrentApplicationCallbackUri().AbsoluteUri;
        }

        public async Task<AuthorizeResult> AuthorizeAsync(bool trySilent = false, object extraParameters = null)
        {
            WebViewInvokeResult wviResult;
            AuthorizeResult result = new AuthorizeResult
            {
                IsError = true,
            };

            // todo: replace with CryptoRandom
            result.Nonce = Guid.NewGuid().ToString("N");
            result.RedirectUri = _options.RedirectUri;
            string codeChallenge = CreateCodeChallenge(result);
            var url = await CreateUrlAsync(result, codeChallenge, extraParameters);
            
            // try silent mode if requested
            if (trySilent)
            {
                try
                {
                    wviResult = await _options.WebView.InvokeAsync(url, _options.RedirectUri, true);

                    if (wviResult.Success)
                    {
                        return await ParseResponse(wviResult.Response, result);
                    }
                }
                catch (InvalidOperationException ex)
                {
                    result.Error = ex.InnerException.Message;
                    return result;
                }
            }

            // fall back to interactive mode
            try
            {
                wviResult = await _options.WebView.InvokeAsync(url, _options.RedirectUri);
            }
            catch (InvalidOperationException ex)
            {
                result.Error = ex.InnerException.Message;
                return result;
            }

            return await ParseResponse(wviResult.Response, result);
        }

        public async Task EndSessionAsync(string identityToken = null, bool trySilent = true)
        {
            string url = (await _options.GetEndpointsAsync()).EndSession;

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

        private string CreateCodeChallenge(AuthorizeResult result)
        {
            if (_options.UseProofKeys)
            {
                // todo: replace with CryptoRandom
                result.Verifier = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
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

        private async Task<string> CreateUrlAsync(AuthorizeResult result, string codeChallenge, object extraParameters)
        {
            var request = new AuthorizeRequest((await _options.GetEndpointsAsync()).Authorize);
            var url = request.CreateAuthorizeUrl(
                clientId: _options.ClientId,
                responseType: OidcConstants.ResponseTypes.CodeIdToken,
                scope: _options.Scope,
                redirectUri: result.RedirectUri,
                responseMode: OidcConstants.ResponseModes.FormPost,
                nonce: result.Nonce,
                codeChallenge: codeChallenge,
                codeChallengeMethod: _options.UseProofKeys ? OidcConstants.CodeChallengeMethods.Sha256 : null,
                extra: extraParameters);

            return url;
        }

        private Task<AuthorizeResult> ParseResponse(string webViewResponse, AuthorizeResult result)
        {
            var response = new AuthorizeResponse(webViewResponse);

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