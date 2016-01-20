using Authentication;
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
        Authentication.OidcClient _client;
        LoginResult _result;

        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void buttonLogin_Click(object sender, RoutedEventArgs e)
        {
            if (_client == null)
            {
                var settings = new OidcSettings("uwp", "secret", "openid write");
                await settings.LoadEndpointsFromMetadataAsync("https://localhost:44333/core");

                _client = new Authentication.OidcClient(settings);
            }

            _result = await _client.LoginAsync();
            ShowLoginResult();
        }

        private async void buttonLogout_Click(object sender, RoutedEventArgs e)
        {
            _result = null;
            textBox.Text = "";

            await _client.LogoutAsync();
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