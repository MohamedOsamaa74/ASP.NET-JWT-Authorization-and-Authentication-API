using AutoMapper;
using Azure;
using JWTAuthenticationAPI.DTOS;
using JWTAuthenticationAPI.Helpers;
using JWTAuthenticationAPI.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthenticationAPI.Services
{
    public class AccountService : IAccountService
    {

        #region Dependency Injection
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JWT _jwt;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly MailSettings _mailSettings;
        private static readonly Dictionary<string, (string OTP, DateTime Expiry)> _otpCache
        = new Dictionary<string, (string OTP, DateTime Expiry)>();
        public AccountService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IMapper mapper, IHttpContextAccessor httpContextAccessor, SignInManager<ApplicationUser>signInManager, IOptions<MailSettings>mailSettings)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _roleManager = roleManager;
            _config = configuration;
            _mapper = mapper;
            _httpContextAccessor = httpContextAccessor;
            _signInManager = signInManager;
            _mailSettings = mailSettings.Value;
        }
        #endregion

        #region Get Current User
        public async Task<ApplicationUser> GetCurrentUserAsync()
        {
            ClaimsPrincipal currentUser = _httpContextAccessor.HttpContext.User;
            return await _userManager.GetUserAsync(currentUser);
        }
        #endregion

        #region Register User
        public async Task<AuthDTO> RegisterUserAsync(RegisterDTO Model)
        {
            if(await _userManager.FindByEmailAsync(Model.Email) != null || await _userManager.FindByNameAsync(Model.UserName) != null)
            {
                return new AuthDTO { Message = "User is already registered" };
            }
            var user = _mapper.Map<ApplicationUser>(Model);
            var result = await _userManager.CreateAsync(user, Model.Password);
            if (!result.Succeeded)
            {
                return new AuthDTO { Message = "User Registration Failed", Errors = result.Errors.Select(e => e.Description) };
            }
            await _userManager.AddToRoleAsync(user, "User");
            var token = await CreateTokenAsync(user);
            return new AuthDTO {
                Message = $"Welcome On Board{user.FirstName}",
                UserName = user.UserName, Email = user.Email,
                //ExpiresOn = token.ValidTo,
                IsAuthenticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Roles = new List<string> { "User" },
            };
        }
        #endregion

        #region Log In
        public async Task<AuthDTO> LogIn(LoginDTO Model)
        {
            var authModel = new AuthDTO();
            try
            {
                var user = await _userManager.FindByNameAsync(Model.UserName);
                if (user == null || !await _userManager.CheckPasswordAsync(user, Model.Password))
                {
                    return new AuthDTO { Message = "Invalid Authentication" };
                }
                var token = await CreateTokenAsync(user);
                var roles = await _userManager.GetRolesAsync(user);

                authModel.Message = $"Welcome Back, {user.FirstName}";
                authModel.UserName = user.UserName;
                authModel.Email = user.Email;
                authModel.Token = new JwtSecurityTokenHandler().WriteToken(token);
                authModel.IsAuthenticated = true; //ExpiresOn = token.ValidTo,
                authModel.Roles = roles.ToList();

                if (user.RefreshTokens.Any(a => a.IsActive))
                {
                    var ActiveRefreshToken = user.RefreshTokens.First(a => a.IsActive);
                    authModel.RefreshToken = ActiveRefreshToken.Token;
                    authModel.RefreshTokenExpiration = ActiveRefreshToken.ExpiresOn;
                }
                else
                {
                    var refreshToken = GenerateRefreshToken();
                    user.RefreshTokens.Add(refreshToken);
                    await _userManager.UpdateAsync(user);
                    authModel.RefreshToken = refreshToken.Token;
                    authModel.RefreshTokenExpiration = refreshToken.ExpiresOn;
                }
                return authModel;
            }
            catch (Exception ex)
            {
                return new AuthDTO { Message = "Invalid Authentication", Errors = new List<string> { ex.Message } };
            }
        }
        #endregion

        #region Change Password
        public async Task<AuthDTO> ChangePasswordAsync(ChangePasswordDTO Model)
        {
            AuthDTO Auth = new AuthDTO();
            try
            {
                var user = await GetCurrentUserAsync();
                if(user is null)
                {
                    return new AuthDTO { Message = "User Not Found" };
                }
                if (!await _userManager.CheckPasswordAsync(user, Model.CurrentPassword))
                {
                    return new AuthDTO { Message = "Invalid Password" };
                }
                var result = await _userManager.ChangePasswordAsync(user, Model.CurrentPassword, Model.NewPassword);
                if (result.Succeeded)
                {
                    await _signInManager.RefreshSignInAsync(user);
                    Auth.Message = "Password Changed Successfully";
                    Auth.IsAuthenticated = true;
                    Auth.UserName = user.UserName; Auth.Email = user.Email;
                }
                else
                {
                    Auth.Message = "Password Change Failed"; Auth.UserName = user.UserName;
                    Auth.Email = user.Email;
                    Auth.Errors = result.Errors.Select(e => e.Description);
                }
                return Auth;
            }
            catch (Exception ex)
            {
                return new AuthDTO { Message = "Password Change Failed", Errors = new List<string> { ex.Message } };
            }
        }
        #endregion

        #region Create Role
        public async Task<string> CreateRoleAsync(string RoleName)
        {
            if (await _roleManager.RoleExistsAsync(RoleName))
                return "Role Already Exist";
            await _roleManager.CreateAsync(new IdentityRole(RoleName));
            return "Role Created Successfully";
        }
        #endregion

        #region Delete Role
        public async Task<string> DeleteRoleAsync(string RoleId)
        {
            var role = await _roleManager.FindByIdAsync(RoleId);
            if (role == null)
            {
                return "Role Not Found";
            }
            var result = await _roleManager.DeleteAsync(role);
            return result.Succeeded ? "Role Deleted Successfully" : "Role Deletion Failed";
        }
        #endregion

        #region Add To Role
        public async Task<string> AddToRoleAsync(UserRoleDTO Model)
        {
            var user = await _userManager.FindByNameAsync(Model.UserName);
            if (user == null)
            {
                return "User Not Found";
            }
            if(!await _roleManager.RoleExistsAsync(Model.Role))
            {
                return "Role Not Found";
            }
            var result = await _userManager.AddToRoleAsync(user, Model.Role);
            return result.Succeeded ? "User Assigned To Role Successfully" : "Role Addition Failed";
        }
        #endregion

        #region Remove From Role
        public async Task<string> RemoveFromRoleAsync(UserRoleDTO Model)
        {
            var user = await _userManager.FindByNameAsync(Model.UserName);
            if (user == null)
            {
                return "User Not Found";
            }
            if (!await _roleManager.RoleExistsAsync(Model.Role))
            {
                return "Role Not Found";
            }
            var result = await _userManager.RemoveFromRoleAsync(user, Model.Role);
            return result.Succeeded ? "User Removed From Role Successfully" : "Role Removal Failed";
        }
        #endregion

        #region Create Token
        private async Task<JwtSecurityToken> CreateTokenAsync(ApplicationUser user)
        {
            #region claims
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, user.UserName));
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            #endregion

            #region get roles
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));
            #endregion

            #region sign-in credintials
            SecurityKey securityKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            SigningCredentials signingCred = new SigningCredentials
                (securityKey, SecurityAlgorithms.HmacSha256);
            #endregion

            #region create token
            JwtSecurityToken token = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(_jwt.DurationInHours),
                signingCredentials: signingCred
            );
            #endregion

            return token;
        }
        #endregion

        #region Delete User
        public async Task<string> DeleteUserAsync(string UserId)
        {
            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                return "User Not Found";
            }
            var result = await _userManager.DeleteAsync(user);
            return result.Succeeded ? "User Deleted Successfully" : "User Deletion Failed";
        }
        #endregion

        #region Logout
        public async Task<string> LogoutAsync()
        {
            var refreshToken = _httpContextAccessor.HttpContext.Request.Cookies["refreshToken"];
            var user = _userManager.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == refreshToken));
            if (user == null)
            {
                return "Invalid token";
            }

            var oldRefreshToken = user.RefreshTokens.Single(x => x.Token == refreshToken);
            if (!oldRefreshToken.IsActive)
            {
                return "Inactive token";
            }

            oldRefreshToken.RevokedOn = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Clear the refresh token cookie
            _httpContextAccessor.HttpContext.Response.Cookies.Delete("refreshToken");

            return "Logged out successfully";
        }
        #endregion

        #region Send Email
        public async Task<EmailDTO> SendEmailAsync(EmailDTO Model)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_mailSettings.DisplayName, _mailSettings.Mail));
            message.To.Add(new MailboxAddress("", Model.Email));
            message.Subject = Model.Subject;
            var builder = new BodyBuilder
            {
                HtmlBody = Model.Body
            };
            if (Model.Attachements != null)
            {
                byte[] fileBytes;
                foreach (var file in Model.Attachements)
                {
                    if (file.Length > 0)
                    {
                        using (var ms = new MemoryStream())
                        {
                            await file.CopyToAsync(ms);
                            fileBytes = ms.ToArray();
                        }
                        builder.Attachments.Add(file.FileName, fileBytes, ContentType.Parse(file.ContentType));
                    }
                }
            }
            message.Body = builder.ToMessageBody();
            using (var client = new SmtpClient())
            {
                client.Connect(_mailSettings.Host, _mailSettings.Port, SecureSocketOptions.StartTls);
                client.Authenticate(_mailSettings.Mail, _mailSettings.Password);
                await client.SendAsync(message);
                client.Disconnect(true);
            }
            return Model;
        }
        #endregion

        #region Send Confirmation Email
        public async Task<string> SendConfirmationEmailAsync(string Email)
        {
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                return "User Not Found";
            }
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var confirmationLink = _httpContextAccessor.HttpContext.Request.Host + $"/api/Account/ConfirmEmail?Token={token}";
            //var confirmationLink = _httpContextAccessor.HttpContext.Request.GetDisplayUrl() + $"/api/Account/ConfirmEmail?Token={WebUtility.UrlEncode(token)}";
            var confirmationLink = $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/api/Account/ConfirmEmail?Token={token}";
            var message = new EmailDTO
            {
                Email = Email,
                Subject = "Email Confirmation",
                Body = $"<h1>Welcome {user.UserName}</h1><br>" +
                $"<p>Please Confirm Your Email By <a href='{confirmationLink}'>Clicking Here</a></p>"
            };
            await SendEmailAsync(message);
            return "Confirmation Email Sent Successfully";
        }
        #endregion

        #region Confirm Email
        public async Task<string> ConfirmEmailAsync(string Token)
        {
            var user = await GetCurrentUserAsync();
            if (user == null)
            {
                return "User Not Found";
            }
            var result = await _userManager.ConfirmEmailAsync(user, Token);
            return result.Succeeded ? "Email Confirmed Successfully" : "Email Confirmation Failed";
        }
        #endregion

        #region Forgot Password
        public async Task<string> ForgotPasswordAsync(string Email)
        {
            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                return "User Not Found";
            }
            var otp = GenerateOTP(Email);
            try
            {
                var emailDTO = new EmailDTO
                {
                    Email = Email,
                    Subject = "Password Reset",
                    Body = $"<h1>Reset Your Password</h1><br>" +
                    $"<p>Your OTP is {otp}</p>"
                };
                await SendEmailAsync(emailDTO);
                return "OTP Sent Successfully";
            }
            catch (Exception ex)
            {
                return $"An Error Occurred, {ex.Message}";
            }
        }
        #endregion

        #region Verify OTP
        public async Task<string> VerifyOTPAsync(VerifyOTPDTO Model)
        {
            if (!VerifyOTP(Model.Email, Model.OTP))
            {
                return "Invalid OTP";
            }
            var user = await _userManager.FindByEmailAsync(Model.Email);
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            return token;
        }
        #endregion

        #region Reset Password
        public async Task<string> ResetPasswordAsync(ResetPasswordDTO Model)
        {
            var user = await _userManager.FindByEmailAsync(Model.Email);
            if (user == null)
            {
                return "User Not Found";
            }
            var token = Model.resetPasswordToken;
            if (token == null)
            {
                return "Invalid Token";
            }
            if(Model.NewPassword != Model.ConfirmPassword)
            {
                return "Passwords Do Not Match";
            }
            var result = await _userManager.ResetPasswordAsync(user, token, Model.NewPassword);
            return result.Succeeded ? "Password Reset Successfully" : $"Password Reset Failed{result.Errors.FirstOrDefault().Description}";
        }
        #endregion

        #region Generate Refresh Token
        private RefreshToken GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return new RefreshToken()
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddDays(7),
                CreatedOn = DateTime.UtcNow,
            };
        }
        #endregion

        #region Refresh Token
        public async Task<AuthDTO> RefreshTokenAsync()
        {
            try
            {
                //var RefreshToken = _httpContextAccessor.HttpContext.Request.Cookies["RefreshToken"];
                var RefreshToken = GetRefreshTokenFromCookie();
                if (string.IsNullOrEmpty(RefreshToken))
                    return new AuthDTO { Message = "Invalid Token" };
                var user = _userManager.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == RefreshToken));
                if (user == null)
                    return new AuthDTO { Message = "Invalid Token" };
                var oldRefreshToken = user.RefreshTokens.Single(x => x.Token == RefreshToken);
                if (!oldRefreshToken.IsActive)
                {
                    return new AuthDTO { Message = "InActive Token" };
                }
                oldRefreshToken.RevokedOn = DateTime.UtcNow;
                var newRefreshToken = GenerateRefreshToken();
                user.RefreshTokens.Add(newRefreshToken);
                await _userManager.UpdateAsync(user);
                var jwtToken = await CreateTokenAsync(user);
                AuthDTO auth = new AuthDTO
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    RefreshToken = newRefreshToken.Token,
                    RefreshTokenExpiration = newRefreshToken.ExpiresOn,
                    IsAuthenticated = true,
                    UserName = user.UserName,
                    Email = user.Email,
                    Roles = await _userManager.GetRolesAsync(user) as List<string>,
                };
                SetRefreshTokenInCookie(auth.RefreshToken, auth.RefreshTokenExpiration);
                return auth;
            }
            catch (Exception ex)
            {
                return new AuthDTO { Message = $"An error occurred, {ex.Message}" };
            }
        }
        #endregion

        #region Revoke Token
        public async Task<bool> RevokeTokenAsync(string Token)
        {
            var user = _userManager.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == Token));
            if (user == null)
            {
                return false;
            }
            var refreshToken = user.RefreshTokens.Single(x => x.Token == Token);
            if (!refreshToken.IsActive)
            {
                return false;
            }
            refreshToken.RevokedOn = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            return true;
        }
        #endregion

        #region Set Refresh Token in Cookie
        public void SetRefreshTokenInCookie(string Token, DateTime expires)
        {
            var CoockieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expires,
            };
            _httpContextAccessor.HttpContext.Response.Cookies.Append("refreshToken", Token, CoockieOptions);
        }
        #endregion

        #region GetRefreshTokenFromCookie
        private string GetRefreshTokenFromCookie()
        {
            return _httpContextAccessor.HttpContext.Request.Cookies["refreshToken"];
        }
        #endregion

        #region Generate OTP
        public string GenerateOTP(string email)
        {
            Random random = new Random();
            string otp = random.Next(100000, 999999).ToString();
            _otpCache[email] = (otp, DateTime.UtcNow.AddMinutes(5)); // OTP expires in 5 minutes
            return otp;
        }
        #endregion

        #region Verify OTP
        public bool VerifyOTP(string email, string otp)
        {
            if (_otpCache.ContainsKey(email) && _otpCache[email].OTP == otp && _otpCache[email].Expiry > DateTime.UtcNow)
            {
                _otpCache.Remove(email);
                return true;
            }
            return false;
        }
        #endregion
    }
}