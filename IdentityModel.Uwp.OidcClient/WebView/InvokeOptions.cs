namespace IdentityModel.Uwp.OidcClient.WebView
{
    public class InvokeOptions
    {
        public string StartUrl { get; }
        public string EndUrl { get; }
        public ResponseMode ResponseMode { get; set; } = ResponseMode.FormPost;
        public DisplayMode InitialDisplayMode { get; set; } = DisplayMode.Visible;
        public int Timeout { get; set; } = 10;

        public InvokeOptions(string startUrl, string endUrl)
        {
            StartUrl = startUrl;
            EndUrl = endUrl;
        }
    }
}
