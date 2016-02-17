using System;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient.WebView
{
    public interface IWebView
    {
        Task<InvokeResult> InvokeAsync(InvokeOptions options);

        event EventHandler<HiddenModeFailedEventArgs> HiddenModeFailed;
    }
}
