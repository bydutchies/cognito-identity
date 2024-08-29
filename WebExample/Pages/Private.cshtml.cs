using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Linq;
using System.Threading.Tasks;

namespace WebExample.Pages;

public class PrivateModel : PageModel
{
    private readonly CognitoUserManager<CognitoUser> _userManager;
    private readonly CognitoSignInManager<CognitoUser> _signInManager;

    public PrivateModel(UserManager<CognitoUser> userManger, SignInManager<CognitoUser> signInManager)
    {
        _userManager = userManger as CognitoUserManager<CognitoUser>;
        _signInManager = signInManager as CognitoSignInManager<CognitoUser>;
    }

    public string AccessToken { get; set; }

    public string IdToken { get; set; }

    public string RefreshToken { get; set; }

    public async Task OnGet()
    {
        await SetTokens();
    }

    public async Task OnPostResetMfa()
    {
        await SetTokens();
        await _userManager.SetUserMFAPreferenceAsync(AccessToken, false);
    }

    public async Task OnPostRefreshTokens()
    {
        var email = User.Claims.First(x => x.Type == "email").Value;
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return;
        }

        await _signInManager.RefreshSignInAsync(user);

        // Vernieuwen
        await SetTokens();
    }

    private async Task SetTokens()
    {
        AccessToken = await HttpContext.GetTokenAsync("access_token");
        IdToken = await HttpContext.GetTokenAsync("id_token");
        RefreshToken = await HttpContext.GetTokenAsync("refresh_token");
    }
}