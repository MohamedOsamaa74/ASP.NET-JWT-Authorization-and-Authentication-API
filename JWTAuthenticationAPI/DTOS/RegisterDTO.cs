using System.ComponentModel.DataAnnotations;

namespace JWTAuthenticationAPI.DTOS
{
    public class RegisterDTO
    {
        [Required, MaxLength(50)]
        public required string FirstName { get; set; }
        [Required, MaxLength(50)]
        public required string LastName { get; set; }
        [Required, MaxLength(50)]
        public required string UserName { get; set; }
        [Required, MaxLength(50)]
        public required string Email { get; set; }
        [Required, MaxLength(50)]
        public required string Password { get; set; }
    }
}
