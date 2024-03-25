namespace JWTAuthenticationAPI.DTOS
{
    public class EmailDTO
    {
        public required string Email { get; set; }
        public required string Subject { get; set; }
        public required string Body { get; set; }
        public IList<IFormFile>? Attachements { get; set; }
    }
}
