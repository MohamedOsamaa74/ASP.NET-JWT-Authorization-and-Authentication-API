using Microsoft.AspNetCore.Identity;

namespace JWTAuthenticationAPI.Models
{
    public class ApplicationUser : IdentityUser
    {
        public required string FirstName { get; set; }
        public required string LastName { get; set; }
        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}
