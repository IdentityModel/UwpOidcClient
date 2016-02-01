using IdentityModel.Uwp.OidcClient;
using System.Text;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace OidcClient
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        IdentityModel.Uwp.OidcClient.OidcClient _client;
        LoginResult _result;

        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void buttonLogin_Click(object sender, RoutedEventArgs e)
        {
            if (_client == null)
            {
                var settings = new OidcClientSettings("uwp", "secret", "openid profile write");
                settings.UseProofKeys = true;

                await settings.LoadEndpointsFromMetadataAsync("https://localhost:44333/core");

                _client = new IdentityModel.Uwp.OidcClient.OidcClient(settings);
            }

            _result = await _client.LoginAsync();
            ShowLoginResult();
        }

        private async void buttonLogout_Click(object sender, RoutedEventArgs e)
        {
            await _client.LogoutAsync(_result.IdentityToken);

            _result = null;
            textBox.Text = "";
        }

        private void ShowLoginResult()
        {
            if (!_result.Success)
            {
                textBox.Text = _result.Error;
                return;
            }

            var sb = new StringBuilder(128);

            foreach (var claim in _result.Principal.Claims)
            {
                sb.AppendLine($"{claim.Type}: {claim.Value}");
            }

            sb.AppendLine($"access token: {_result.AccessToken}");
            sb.AppendLine($"access token expiration: {_result.AccessTokenExpiration}");

            textBox.Text = sb.ToString();
        }

        private void buttonStore_Click(object sender, RoutedEventArgs e)
        {
            if (_result != null)
            {
                _result.Store();
                textBox.Text = "OK";
            }
        }

        private void buttonRetrieve_Click(object sender, RoutedEventArgs e)
        {
            var result = LoginResult.Retrieve();

            if (result != null)
            {
                _result = result;
                ShowLoginResult();
            }
            else
            {
                textBox.Text = "no result, or expired";
            }
        }
    }
}