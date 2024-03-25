using JWTAuthenticationAPI.Const;
using JWTAuthenticationAPI.Models;
using Microsoft.AspNetCore.Identity;

namespace JWTAuthenticationAPI.Data
{
    public class AppDbInitializer
    {
        public static async Task SeedUsersandRolesAsync(IApplicationBuilder applicationBuilder)
        {
            using (var serviceScope = applicationBuilder.ApplicationServices.CreateScope())
            {
                var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

                if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
                {
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
                }

                if (!await roleManager.RoleExistsAsync(UserRoles.User))
                {
                    await roleManager.CreateAsync(new IdentityRole(UserRoles.User));
                }

                var adminUser = await userManager.FindByNameAsync("Admin");

                if (adminUser == null)
                {
                    var newAdminUser = new ApplicationUser()
                    {
                        FirstName = "admin",
                        LastName = "User",
                        UserName = "Admin",
                        Email = "Admin@gmail.com"
                    };
                    await userManager.CreateAsync(newAdminUser, "Admin@123");
                    await userManager.AddToRoleAsync(newAdminUser, UserRoles.Admin);
                }
                var normalUser = await userManager.FindByNameAsync("User");
                if(normalUser == null)
                {
                    var newNormalUser = new ApplicationUser()
                    {
                        FirstName = "Normal",
                        LastName = "User",
                        UserName = "User",
                        Email = "User@gmail.com"
                    };
                    await userManager.CreateAsync(newNormalUser, "User@123");
                    await userManager.AddToRoleAsync(newNormalUser, UserRoles.User);
                }
            }
        }
    }
}
