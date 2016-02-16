using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;

namespace IdentityModel.Uwp.OidcClient
{
    public class UwpWebView : WebViewBase
    {
        private readonly bool _enableWindowsAuthentication;

        public UwpWebView(bool enableWindowsAuthentication = false)
        {
            _enableWindowsAuthentication = enableWindowsAuthentication;
        }

        protected override async Task<WebViewInvokeResult> InvokeAsyncCore(string startUrl, string endUrl, bool trySilent, int timeout)
        {
            var wabOptions = WebAuthenticationOptions.UseHttpPost;

            if (trySilent)
            {
                wabOptions |= WebAuthenticationOptions.SilentMode;
            }
            if (_enableWindowsAuthentication)
            {
                wabOptions |= WebAuthenticationOptions.UseCorporateNetwork;
            }

            WebAuthenticationResult wabResult;

            if (string.Equals(endUrl, WebAuthenticationBroker.GetCurrentApplicationCallbackUri().AbsoluteUri, StringComparison.Ordinal))
            {
                wabResult = await WebAuthenticationBroker.AuthenticateAsync(
                    wabOptions, new Uri(startUrl));
            }
            else
            {
                wabResult = await WebAuthenticationBroker.AuthenticateAsync(
                    wabOptions, new Uri(startUrl), new Uri(endUrl));
            }

            if (wabResult.ResponseStatus == WebAuthenticationStatus.Success)
            {
                return new WebViewInvokeResult
                {
                    Success = true,
                    Response = wabResult.ResponseData
                };
            }
            else
            {
                return new WebViewInvokeResult
                {
                    Success = false,
                    Error = string.Concat("HTTP error ", wabResult.ResponseErrorDetail)
                };
            }
        }
    }
}
