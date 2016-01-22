// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient
{
    public class OidcSettings
    {
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; set; }

        public bool EnableWindowsAuthentication { get; set; }
        public bool LoadProfile { get; set; } = true;
        public bool FilterProtocolClaims { get; set; } = true;

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

            var doc = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

            Endpoints = new Endpoints
            {
                Authorize = doc["authorization_endpoint"].ToString(),
                Token = doc["token_endpoint"].ToString(),
                EndSession = doc["end_session_endpoint"].ToString(),
                UserInfo = doc["userinfo_endpoint"].ToString(),
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
        public string UserInfo { get; set; }
    }
}