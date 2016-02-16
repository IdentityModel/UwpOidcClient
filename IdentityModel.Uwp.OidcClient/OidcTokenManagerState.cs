using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.Uwp.OidcClient
{
    internal class OidcTokenManagerState
    {
        internal OidcClientOptions Options { get; set; }
        internal LoginResult LoginResult { get; set; }
    }
}
