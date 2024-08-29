using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;

namespace WebExample.Areas.Identity.Pages.Account;

[AllowAnonymous]
public class ConfirmAccountModel : PageModel
{
    private readonly CognitoUserManager<CognitoUser> _userManager;
    private readonly CognitoSignInManager<CognitoUser> _signInManager;

    public ConfirmAccountModel(
        UserManager<CognitoUser> userManager, SignInManager<CognitoUser> signInManager)
    {
        _userManager = userManager as CognitoUserManager<CognitoUser>;
        _signInManager = signInManager as CognitoSignInManager<CognitoUser>;
    }

    [BindProperty]
    public InputModel Input { get; set; }

    public string ReturnUrl { get; set; }

    public string Email { get; set; }

    public class InputModel
    {
        [Required]
        [Display(Name = "Code")]
        public string Code { get; set; }
    }

    public void OnGet(string email, string returnUrl = null)
    {
        Email = email;
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(string email, string returnUrl = null)
    {
        returnUrl = returnUrl ?? Url.Content("~/");
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return NotFound($"Unable to load user with email '{email}'.");
            }

            var result = await _userManager.ConfirmSignUpAsync(user, Input.Code, true);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Error confirming account for user with email '{email}':");
            }
            else
            {
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }
        }

        // If we got this far, something failed, redisplay form
        return Page();
    }
}
