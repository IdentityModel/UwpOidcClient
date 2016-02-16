using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient
{
    public class WebViewInvokeResult
    {
        public bool Success { get; set; }
        public string Response { get; set; }
        public string Error { get; set; }
    }
}
