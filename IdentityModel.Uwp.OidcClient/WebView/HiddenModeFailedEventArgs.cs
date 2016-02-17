using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient.WebView
{
    public class HiddenModeFailedEventArgs : CancelEventArgs
    {
        public InvokeResult Result { get; }

        public HiddenModeFailedEventArgs(InvokeResult result)
        {
            Result = result;
        }
    }
}
