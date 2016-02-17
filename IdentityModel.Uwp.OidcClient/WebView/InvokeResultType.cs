using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient.WebView
{
    public enum InvokeResultType
    {
        Success,
        HttpError,
        UserCancel,
        Timeout,
        UnknownError
    }
}
