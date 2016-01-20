namespace Authentication
{
    public class AuthorizeResult
    {
        public bool IsError { get; set; }
        public string Error { get; set; }

        public string IdentityToken { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public string Nonce { get; set; }
    }
}