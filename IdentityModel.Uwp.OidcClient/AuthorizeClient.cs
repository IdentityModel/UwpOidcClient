// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using System;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;

namespace IdentityModel.Uwp.OidcClient
{
    public class AuthorizeClient
    {
        private readonly OidcSettings _settings;
        
        public AuthorizeClient(OidcSettings settings)
        {
            _settings = settings;
        }

        public static string GetCallbackUrl()
        {
            return WebAuthenticationBroker.GetCurrentApplicationCallbackUri().AbsoluteUri;
        }

        public async Task<AuthorizeResult> StartAsync(bool trySilent = false)
        {
            var callback = WebAuthenticationBroker.GetCurrentApplicationCallbackUri();
            var nonce = Guid.NewGuid().ToString("N");

            var request = new AuthorizeRequest(_settings.Endpoints.Authorize);
            var url = request.CreateAuthorizeUrl(
                _settings.ClientId,
                "code",
                _settings.Scope,
                callback.AbsoluteUri,
                nonce: nonce,
                responseMode: "form_post");

            WebAuthenticationResult authenticationResult;
            AuthorizeResult result = new AuthorizeResult
            {
                IsError = true,
                Nonce = nonce
            };

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

                    authenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                        options, new Uri(url));

                    if (authenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                    {
                        return await FillTokens(authenticationResult, result);
                        
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

                authenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                    WebAuthenticationOptions.UseHttpPost, new Uri(url));
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                return result;
            }

            return await FillTokens(authenticationResult, result);
        }

        private async Task<AuthorizeResult> FillTokens(WebAuthenticationResult authenticationResult, AuthorizeResult result)
        {
            var response = new AuthorizeResponse(authenticationResult.ResponseData);

            if (response.IsError)
            {
                result.Error = response.Error;
                return result;
            }

            if (string.IsNullOrEmpty(response.Code))
            {
                result.Error = "Missing authorization code";
                return result;
            }

            // exchange code with tokens
            var callback = WebAuthenticationBroker.GetCurrentApplicationCallbackUri();
            var tokenClient = new TokenClient(_settings.Endpoints.Token, _settings.ClientId, _settings.ClientSecret);
            var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(response.Code, callback.AbsoluteUri);

            if (tokenResponse.IsError || tokenResponse.IsHttpError)
            {
                result.Error = tokenResponse.Error ?? tokenResponse.HttpErrorReason;
                return result;
            }

            result.AccessToken = tokenResponse.AccessToken;
            result.IdentityToken = tokenResponse.IdentityToken;
            result.RefreshToken = tokenResponse.RefreshToken;
            result.ExpiresIn = (int)tokenResponse.ExpiresIn;
            result.IsError = false;

            return result;
        }
    }
}