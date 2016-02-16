using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient
{
    public class OidcClientOptions
    {
        private readonly Lazy<Task<Endpoints>> _endpoints;

        public string ClientId { get; }
        public string ClientSecret { get; }
        public string Scope { get; }
        public Flow Flow { get; set; } = Flow.Hybrid;
        public bool EnableWindowsAuthentication { get; set; } = false;
        public bool LoadProfile { get; set; } = true;
        public bool FilterClaims { get; set; } = true;
        public bool UseProofKeys { get; set; } = true;

        public IList<string> FilteredClaims { get; set; } = new List<string>
        {
            JwtClaimTypes.Issuer,
            JwtClaimTypes.Expiration,
            JwtClaimTypes.NotBefore,
            JwtClaimTypes.Audience,
            JwtClaimTypes.Nonce,
            JwtClaimTypes.IssuedAt,
            JwtClaimTypes.AuthenticationTime,
            JwtClaimTypes.AuthorizationCodeHash,
            JwtClaimTypes.AccessTokenHash
        };

        public OidcClientOptions(Endpoints endpoints, string clientId, string clientSecret, string scope)
        {
            if (endpoints == null) throw new ArgumentNullException(nameof(endpoints));
            endpoints.Validate();
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));
            if (string.IsNullOrWhiteSpace(scope)) throw new ArgumentNullException(nameof(scope));

            _endpoints = new Lazy<Task<Endpoints>>(() => Task.FromResult(endpoints));
            ClientId = clientId;
            ClientSecret = clientSecret;
            Scope = scope;
        }

        public OidcClientOptions(string authority, string clientId, string clientSecret, string scope)
        {
            if (string.IsNullOrWhiteSpace(authority)) throw new ArgumentNullException(nameof(authority));
            if (string.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret)) throw new ArgumentNullException(nameof(clientSecret));
            if (string.IsNullOrWhiteSpace(scope)) throw new ArgumentNullException(nameof(scope));

            _endpoints = new Lazy<Task<Endpoints>>(async () => await Endpoints.LoadFromMetadataAsync(authority));
            ClientId = clientId;
            ClientSecret = clientSecret;
            Scope = scope;
        }

        public async Task<Endpoints> GetEndpointsAsync()
        {
            return await _endpoints.Value;
        }
    }
}
