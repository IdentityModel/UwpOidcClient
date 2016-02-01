// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Newtonsoft.Json;
using System;
using System.Security.Claims;
using Windows.Security.Credentials;

namespace IdentityModel.Uwp.OidcClient
{
    public class LoginResult
    {
        private static JsonSerializerSettings settings;

        public bool Success { get; set; }
        public string Error { get; set; }

        public ClaimsPrincipal Principal { get; set; }
        public string AccessToken { get; set; }
        public string IdentityToken { get; set; }
        public string RefreshToken { get; set; }

        public DateTime AccessTokenExpiration { get; set; }
        public DateTime AuthenticationTime { get; set; }

        public int SecondsBeforeRenewRequired { get; set; } = 60;

        static LoginResult()
        {
            settings = new JsonSerializerSettings();
            settings.Converters.Add(new ClaimsPrincipalConverter());
        }

        public static LoginResult Retrieve(string resourceName = "oidc")
        {
            var vault = new PasswordVault();
            PasswordCredential credential;

            try
            {
                credential = vault.Retrieve(resourceName, "login_result");
            }
            catch (Exception)
            {
                return null;
            }

            var result = JsonConvert.DeserializeObject<LoginResult>(credential.Password, settings);

            if (result.IsAccessTokenValid)
            {
                return result;
            }

            return null;
        }

        [JsonIgnore]
        public bool IsAccessTokenValid
        {
            get
            {
                return DateTime.Now < AccessTokenExpiration.AddSeconds(- SecondsBeforeRenewRequired);
            }
        }

        public void Store(string resourceName = "oidc")
        {
            var vault = new PasswordVault();

            try
            {
                var creds = vault.FindAllByResource("oidc");
                foreach (var cred in creds)
                {
                    vault.Remove(cred);
                }
            }
            catch { }

            var credential = new PasswordCredential(
                resourceName, 
                "login_result",
                JsonConvert.SerializeObject(this, settings));

            vault.Add(credential);
        }
    }
}