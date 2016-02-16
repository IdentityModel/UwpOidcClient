using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient
{
    public abstract class WebViewBase
    {
        protected abstract Task<WebViewInvokeResult> InvokeAsyncCore(string startUrl, string endUrl, bool silent, int timeout);

        public async Task<WebViewInvokeResult> InvokeAsync(string startUrl, string endUrl, bool silent = false, int timeout = 10)
        {
            try
            {
                return await InvokeAsyncCore(startUrl, endUrl, silent, timeout);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Error invoking WebView, see inner exception for details", ex);
            }
        }
    }
}
