using Azure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;

namespace User.Management.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public UserManagement(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {

            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 403, Message = "User already exists!" };
            }

            ApplicationUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };

            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return new ApiResponse<CreateUserResponse> { Response = new CreateUserResponse() { User = user,Token = token }, IsSuccess = true, StatusCode = 201, Message = "User created." };
            } else
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 500, Message = "User failed to create." };
            }
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, ApplicationUser user)
        {
            var assignedRole = new List<string>();
            foreach(var role in roles)
            {
                if(await _roleManager.RoleExistsAsync(role))
                {
                    if (!await _userManager.IsInRoleAsync(user, role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                        assignedRole.Add(role);
                    }
                    
                }
            }
            return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200, Message = "Roles has been assigned", Response = assignedRole };

        }

        public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);

            if (user != null)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

                if (user.TwoFactorEnabled)
                {
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    return new ApiResponse<LoginOtpResponse>
                    {
                        Response = new LoginOtpResponse()
                        {
                            User = user,
                            Token = token,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        },
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = $"OTP send to the email {user.Email}"
                    }; // <T> generic for Response object
                }
                else
                {
                    return new ApiResponse<LoginOtpResponse>
                    {
                        Response = new LoginOtpResponse()
                        {
                            User = user,
                            Token = string.Empty,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        },
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = $"2FA is not enabled"
                    }; // <T> generic for Response object
                }
            } else
            {
                return new ApiResponse<LoginOtpResponse>()
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = $"User does not exist."
                };
            }

        }

        public async Task<ApiResponse<JwtToken>> GetJwtTokenAsync(ApplicationUser user)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }
            //authClaims.AddRange(roleClaims

            var jwtToken = GetToken(authClaims);

            return new ApiResponse<JwtToken>
            {
                IsSuccess = true,
                StatusCode = 201,
                Message = "Token created",
                Response = new JwtToken()
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    ExpiryTokenDate = jwtToken.ValidTo
                }
            };
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
    }
}

