using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient.WebView
{
    public class InvokeResult
    {
        public InvokeResultType ResultType { get; set; }
        public string Response { get; set; }
        public string Error { get; set; }
    }
}
