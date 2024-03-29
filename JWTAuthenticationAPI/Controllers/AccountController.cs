using JWTAuthenticationAPI.DTOS;
using JWTAuthenticationAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthenticationAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;
        public AccountController(IAccountService accountService)
        {
            _accountService = accountService;
        }

        #region Register User
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUserAsync([FromBody] RegisterDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _accountService.RegisterUserAsync(model);
            if (!result.IsAuthenticated)
            {
                return BadRequest(result);
            }
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
            return Ok(result);
        }
        #endregion

        #region Login
        [HttpPost("login")]
        public async Task<IActionResult> LogIn([FromBody] LoginDTO model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _accountService.LogIn(model);
            if (!result.IsAuthenticated)
            {
                return BadRequest(result);
            }
            if (!string.IsNullOrEmpty(result.RefreshToken))
                SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
            return Ok(result);
        }
        #endregion

        #region Refresh Token
        [HttpGet("refresh-token")]
        public async Task<IActionResult> RefreshTokenAsync()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return BadRequest("Invalid Token");
            }
            var result = await _accountService.RefreshTokenAsync(refreshToken);
            if (!result.IsAuthenticated)
            {
                return BadRequest(result);
            }
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
            return Ok(result);
        }
        #endregion

        #region Revoke Token
        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeTokenAsync([FromBody] string Token)
        {
            Token = Token ?? Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(Token))
            {
                return BadRequest("Token is Required");
            }
            var result = await _accountService.RevokeTokenAsync(Token);
            if (result)
            {
                return Ok("Token Revoked Successfully");
            }
            return BadRequest("Token Not Revoked");
        }
        #endregion

        #region Change Password
        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangePasswordDTO model)
        {
            if (ModelState.IsValid)
            {
                var result = await _accountService.ChangePasswordAsync(model);
                if (result.IsAuthenticated)
                {
                    return Ok(result);
                }
                return BadRequest(result);
            }
            return BadRequest(ModelState);
        }
        #endregion

        #region Add To Role
        [HttpPost("add-to-role")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddToRoleAsync([FromBody] UserRoleDTO model)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _accountService.AddToRoleAsync(model);
            if (result == "User Assigned To Role Successfully")
            {
                return Ok(result);
            }
            return BadRequest(result);
        }
        #endregion

        #region LogOut
        [HttpPost("LogOut")]
        [Authorize]
        public async Task<IActionResult>LogOut()
        {
            var result = await _accountService.LogoutAsync();
            if (result == "User Logged Out Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Create Role
        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(string RoleName)
        {
            var result = await _accountService.CreateRoleAsync(RoleName);
            if (result == "Role Already Exist")
                return BadRequest(result);
            return Ok(result);
        }
        #endregion

        #region Remove From Role
        [HttpDelete("RemoveUserFromrole")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult>RemoveFromRole([FromBody]UserRoleDTO Model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _accountService.RemoveFromRoleAsync(Model);
            if (result == "User Removed From Role Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Delete Role
        [HttpDelete("DeleteRole")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteRole(string RoleId)
        {
            var result = await _accountService.DeleteRoleAsync(RoleId);
            if (result == "Role Deleted Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Delete User
        [HttpDelete("DeleteUser")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult>DeleteUser(string UserId)
        {
            var result = await _accountService.DeleteUserAsync(UserId);
            if (result == "User Deleted Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Send Email
        [HttpPost("SendEmail")]
        public async Task<IActionResult> SendEmail([FromForm] EmailDTO Model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _accountService.SendEmailAsync(Model);
            if (result != null)
                return Ok(result);
            return BadRequest("Email Not Sent");
        }
        #endregion

        #region Send Confirmation Email (try without Email Parameter)
        [HttpPost("SendConfirmationEmail")]
        [Authorize]
        public async Task<IActionResult> SendConfirmationEmail(string Email)
        {
            var result = await _accountService.SendConfirmationEmailAsync(Email);
            if (result == "Confirmation Email Sent Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Confirm Email
        [HttpPost("ConfirmEmail/{Token}")]
        [Authorize]
        public async Task<IActionResult> ConfirmEmail(string Token)
        {
            var result = await _accountService.ConfirmEmailAsync(Token);
            if (result == "Email Confirmed Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Forgot Password
        [HttpPost("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(string Email)
        {
            var result = await _accountService.ForgotPasswordAsync(Email);
            if (result == "OTP Sent Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Reset Password
        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDTO Model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _accountService.ResetPasswordAsync(Model); 
            if (result == "Password Reset Successfully")
                return Ok(result);
            return BadRequest(result);
        }
        #endregion

        #region Set Refresh Token in Cookie
        private void SetRefreshTokenInCookie(string Token, DateTime expires)
        {
            var CoockieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expires,
            };
            Response.Cookies.Append("refreshToken", Token, CoockieOptions);
        }
        #endregion
    }
}