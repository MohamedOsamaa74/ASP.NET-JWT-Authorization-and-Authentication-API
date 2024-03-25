using Azure;
using JWTAuthenticationAPI.DTOS;
using JWTAuthenticationAPI.Models;

namespace JWTAuthenticationAPI.Services
{
    public interface IAccountService
    {
        public Task<AuthDTO> RegisterUserAsync(RegisterDTO Model);
        public Task<AuthDTO> LogIn(LoginDTO Model);
        public Task<AuthDTO> ChangePasswordAsync(ChangePasswordDTO Model);
        public Task<ApplicationUser> GetCurrentUserAsync();
        public Task<string> CreateRoleAsync(string RoleName);
        public Task<string> AddToRoleAsync(UserRoleDTO Model);
        public Task<EmailDTO> SendEmailAsync(EmailDTO Model);
        public Task<string> RemoveFromRoleAsync(UserRoleDTO Model);
        public Task<string>DeleteUserAsync(string UserId);
        public Task<string> DeleteRoleAsync(string RoleId);
        public Task<string>LogoutAsync();
        public Task<AuthDTO> RefreshTokenAsync(string Token);
        public Task<bool> RevokeTokenAsync(string Token);
        public Task<string> SendConfirmationEmailAsync(string Email);
        public Task<string> ConfirmEmailAsync(string Token);
        public Task<string> ForgotPasswordAsync(string Email);
        public Task<string> ResetPasswordAsync(ResetPasswordDTO Model);
    }
}
