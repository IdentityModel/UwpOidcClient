// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Newtonsoft.Json;
using System;
using System.Linq;
using System.Security.Claims;

namespace IdentityModel.Uwp.OidcClient
{
    internal class ClaimsPrincipalLite
    {
        public string AuthenticationType { get; set; }
        public ClaimLite[] Claims { get; set; }
    }

    internal class ClaimLite
    {
        public string Type { get; set; }
        public string Value { get; set; }
    }

    internal class ClaimsPrincipalConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return typeof(ClaimsPrincipal) == objectType;
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var source = serializer.Deserialize<ClaimsPrincipalLite>(reader);
            if (source == null) return null;

            var claims = source.Claims.Select(x => new Claim(x.Type, x.Value));
            var id = new ClaimsIdentity(claims, source.AuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);
            var target = new ClaimsPrincipal(id);
            return target;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var source = (ClaimsPrincipal)value;

            var target = new ClaimsPrincipalLite
            {
                AuthenticationType = source.Identity.AuthenticationType,
                Claims = source.Claims.Select(x => new ClaimLite { Type = x.Type, Value = x.Value }).ToArray()
            };
            serializer.Serialize(writer, target);
        }
    }
}