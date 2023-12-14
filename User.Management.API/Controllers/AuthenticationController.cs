﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NETCore.MailKit.Core;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.API.Models;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;
using User.Management.Service.Services;
using IEmailService = User.Management.Service.Services.IEmailService;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _config;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _userManagement;
        public AuthenticationController(UserManager<ApplicationUser> userManager, 
            SignInManager<ApplicationUser> signInManager, 
            IConfiguration config,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            IUserManagement userManagement)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _config = config;
            _roleManager = roleManager;
            _emailService = emailService;
            _userManagement = userManagement;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            var tokenResponse = await _userManagement.CreateUserWithTokenAsync(registerUser);

            if (tokenResponse.IsSuccess)
            {
                await _userManagement.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);

                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Registered & Waiting email verification" });
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Message = tokenResponse.Message, IsSuccess = false });


        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email verified successfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "This user does not exist!" });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _userManagement.GetOtpByLoginAsync(loginModel);

            if (loginOtpResponse.Response != null)
            {
                var user = loginOtpResponse.Response.User;

                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;
                    var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                    _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status200OK,
                        new Response { IsSuccess = loginOtpResponse.IsSuccess, Status = "Success", Message = $"We have send an OTP to your email {user.Email}" });
                }

                if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
                {
                    var response = await _userManagement.GetJwtTokenAsync(user);
                    return Ok(response);
                }
                return Unauthorized();
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var jwt = await _userManagement.LoginUserWithJwtTokenAsync(code, username);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Failed", Message = "Invalid code" });
        }

        [HttpPost("ForgotPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot password link", forgotPasswordLink!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password Changed request is sent on Email {user.Email}. Please open your email & click the link." });

            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = $"Could not send link to email, please try again." });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new
            {
                model
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!resetPasswordResult.Succeeded)
                {
                    foreach(var error in resetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Password has been changed." });

            }
            return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = "Something went wrong while changing the password." });
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(LoginResponse tokens)
        {
            var jwt = await _userManagement.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Failed", Message = "Invalid code" });
        }
    }
}
