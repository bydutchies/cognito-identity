using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace WebExample.Areas.Identity.Pages.Account;

[AllowAnonymous]
public class ChangePasswordModel : PageModel
{
    private readonly CognitoSignInManager<CognitoUser> _signInManager;
    private readonly ILogger<LoginWith2faModel> _logger;

    public ChangePasswordModel(SignInManager<CognitoUser> signInManager, ILogger<LoginWith2faModel> logger)
    {
        _signInManager = signInManager as CognitoSignInManager<CognitoUser>;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; }

    public bool RememberMe { get; set; }

    public string ReturnUrl { get; set; }

    public class InputModel
    {
        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }

    public void OnGet(bool rememberMe, string returnUrl = null)
    {
        RememberMe = rememberMe;
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(bool rememberMe, string returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        returnUrl = returnUrl ?? Url.Content("~/");

        var result = await _signInManager.RespondToPasswordChangeChallengeAsync(Input.NewPassword);
        if (result.Succeeded)
        {
            return LocalRedirect(returnUrl);
        }
        else if (result.RequiresTwoFactor)
        {
            return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = rememberMe });
        }
        else if (result.IsCognitoSignInResult())
        {
            if (result is CognitoSignInResult cognitoResult)
            {
                if (cognitoResult.RequiresMfaSetup)
                {
                    _logger.LogWarning("Mfa needs to be setup");
                    return RedirectToPage("./MfaSetup", new { ReturnUrl = returnUrl, RememberMe = rememberMe });
                }
            }
        }

        return Page();
    }
}
