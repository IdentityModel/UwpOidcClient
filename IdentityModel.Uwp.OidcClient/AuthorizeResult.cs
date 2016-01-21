// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace IdentityModel.Uwp.OidcClient
{
    public class AuthorizeResult
    {
        public bool IsError { get; set; }
        public string Error { get; set; }

        public string IdentityToken { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public string Nonce { get; set; }
    }
}