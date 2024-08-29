using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using QRCoder;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Png;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using static QRCoder.PayloadGenerator;

namespace WebExample.Areas.Identity.Pages.Account;

[AllowAnonymous]
public class MfaSetupModel : PageModel
{
    private readonly CognitoSignInManager<CognitoUser> _signInManager;
    private readonly ILogger<LoginWith2faModel> _logger;

    public MfaSetupModel(SignInManager<CognitoUser> signInManager, ILogger<LoginWith2faModel> logger)
    {
        _signInManager = signInManager as CognitoSignInManager<CognitoUser>;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; }

    public bool RememberMe { get; set; }

    public string ReturnUrl { get; set; }

    public string Base64String { get; set; }

    public class InputModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "2FA code")]
        public string TwoFactorCode { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(bool rememberMe, string returnUrl = null)
    {
        // Ensure the user has gone through the username & password screen first
        var secretCode = await _signInManager.GetMfaSetupSecretCodeAsync();

        if (string.IsNullOrEmpty(secretCode))
            throw new InvalidOperationException($"Unable to load two-factor authentication user.");

        var user = await _signInManager.GetMfaSetupUserAsync();
        if (user == null)
        {
            throw new InvalidOperationException($"Unable to load two-factor authentication user.");
        }

        RememberMe = rememberMe;
        ReturnUrl = returnUrl;
        Base64String = await GetQRCodeAsync(user.Attributes["email"], secretCode);

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(bool rememberMe, string returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        returnUrl = returnUrl ?? Url.Content("~/");

        var user = await _signInManager.GetMfaSetupUserAsync();
        if (user == null)
        {
            throw new InvalidOperationException($"Unable to load two-factor authentication user.");
        }

        var authenticatorCode = Input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
        
        var result = await _signInManager.RespondToMfaSetupChallengeAsync(authenticatorCode, rememberMe);

        if (result.Succeeded)
        {
            _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", user.UserID);
            return LocalRedirect(returnUrl);
        }
        else
        {
            _logger.LogWarning("Invalid 2FA code entered for user with ID '{UserId}'.", user.UserID);
            ModelState.AddModelError(string.Empty, "Invalid 2FA code.");
            return Page();
        }
    }

    #region Private
    /// <summary>
    /// Method to generate QR code
    /// More info: https://github.com/codebude/QRCoder/?tab=readme-ov-file#readme
    /// </summary>
    private async Task<string> GetQRCodeAsync(string email, string secret)
    {
        OneTimePassword generator = new OneTimePassword()
        {
            Secret = secret,
            Issuer = "WebExample",
            Label = email
        };
        string payload = generator.ToString();

        QRCodeGenerator qrGenerator = new QRCodeGenerator();
        QRCodeData qrCodeData = qrGenerator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
        QRCode qrCode = new QRCode(qrCodeData);

        // generate qr code image
        var qrCodeImage = qrCode.GetGraphic(pixelsPerModule: 5);

        return await Task.FromResult(qrCodeImage.ToBase64String(PngFormat.Instance));
    }
    #endregion Private
}
