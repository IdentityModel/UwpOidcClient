using System.ComponentModel;

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
