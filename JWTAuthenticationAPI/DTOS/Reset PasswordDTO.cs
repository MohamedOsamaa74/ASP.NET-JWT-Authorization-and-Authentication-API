namespace JWTAuthenticationAPI.DTOS
{
    public class ResetPasswordDTO
    {
        public required string Email { get; set; }
        public required string OTP { get; set; }
        public required string NewPassword { get; set; }
        public required string ConfirmPassword { get; set; }
    }
}
