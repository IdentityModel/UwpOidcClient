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
        OidcTokenManager _manager;

        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void buttonLogin_Click(object sender, RoutedEventArgs e)
        {
            if (_manager == null)
            {
                var options = new OidcClientOptions("https://localhost:44333/core", "uwp", "secret", "openid profile write");
                _manager = new OidcTokenManager(options);
            }

            await _manager.LoginAsync();
            ShowLoginResult();
        }

        private async void buttonLogout_Click(object sender, RoutedEventArgs e)
        {
            await _manager.LogoutAsync();

            textBox.Text = "";
        }

        private void ShowLoginResult()
        {
            if (_manager.Error != null)
            {
                textBox.Text = _manager.Error;
                return;
            }

            var sb = new StringBuilder(128);

            foreach (var claim in _manager.User.Claims)
            {
                sb.AppendLine($"{claim.Type}: {claim.Value}");
            }

            sb.AppendLine($"access token: {_manager.AccessToken}");

            textBox.Text = sb.ToString();
        }

        private void buttonStore_Click(object sender, RoutedEventArgs e)
        {
            //if (_result != null)
            //{
            //    _result.Store();
            //    textBox.Text = "OK";
            //}
        }

        private void buttonRetrieve_Click(object sender, RoutedEventArgs e)
        {
            //var result = LoginResult.Retrieve();

            //if (result != null)
            //{
            //    _result = result;
            //    ShowLoginResult();
            //}
            //else
            //{
            //    textBox.Text = "no result, or expired";
            //}
        }
    }
}