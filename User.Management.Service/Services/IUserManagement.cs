using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.User;
using Microsoft.AspNetCore.Identity;

namespace User.Management.Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser regiterUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, IdentityUser user);
    }
}
