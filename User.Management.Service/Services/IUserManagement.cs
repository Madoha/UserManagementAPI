using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.User;
using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Data.Models;

namespace User.Management.Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser regiterUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, ApplicationUser user);
        Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel);
        Task<ApiResponse<JwtToken>> GetJwtTokenAsync(ApplicationUser user);
    }
}
