using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace WebExample.Areas.Identity.Pages.Account;

[AllowAnonymous]
public class LogoutModel : PageModel
{
    private readonly CognitoSignInManager<CognitoUser> _signInManager;
    private readonly CognitoUserManager<CognitoUser> _userManager;
    private readonly ILogger<LogoutModel> _logger;

    public LogoutModel(
        SignInManager<CognitoUser> signInManager,
        UserManager<CognitoUser> userManger,
        ILogger<LogoutModel> logger)
    {
        _signInManager = signInManager as CognitoSignInManager<CognitoUser>;
        _userManager = userManger as CognitoUserManager<CognitoUser>;
        _logger = logger;
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPost(string returnUrl = null)
    {
        await _signInManager.SignOutAsync();

        var user = await _userManager.FindByEmailAsync(User.FindFirst("email").Value);
        if (user != null)
        {
            await user.GlobalSignOutAsync(); // Prevent further use issued tokens
            user.SignOut(); // Clean session tokens
        }

        _logger.LogInformation("User logged out.");
        if (returnUrl != null)
        {
            return LocalRedirect(returnUrl);
        }
        else
        {
            return Page();
        }
    }
}