using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient
{
    public class OidcTokenManager
    {
        private readonly OidcTokenManagerState _state;
        private readonly OidcClient _client;

        public OidcTokenManager(OidcClientOptions options)
        {
            _state = new OidcTokenManagerState
            {
                Options = options
            };
            _client = new OidcClient(options);
        }

        public async Task<bool> LoginAsync(bool trySilent = false)
        {
            _state.LoginResult = await _client.LoginAsync(trySilent);
            return _state.LoginResult.Success;
        }

        public async Task SilentRenewAsync()
        {
            var result = await _client.LoginAsync(
                trySilent: true,
                extraParameters: new { prompt = OidcConstants.PromptModes.None });

            if (result.Success)
            {
                _state.LoginResult = result;
            }
        }

        public async Task LogoutAsync(bool trySilent = false)
        {
            await _client.LogoutAsync(_state.LoginResult?.IdentityToken, trySilent);
            _state.LoginResult = null;
        }

        public string AccessToken
        {
            get
            {
                return _state.LoginResult?.AccessToken;
            }
        }

        public ClaimsPrincipal User
        {
            get
            {
                return _state.LoginResult?.Principal ?? new ClaimsPrincipal(new ClaimsIdentity());
            }
        }

        public DateTime? AuthenticationTime
        {
            get
            {
                return _state.LoginResult?.AuthenticationTime;
            }
        }

        public string Error
        {
            get
            {
                return _state.LoginResult?.Error;
            }
        }
    }
}
