using Amazon.AspNetCore.Identity.Cognito;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Linq;

namespace WebExample;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCognitoIdentity(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedAccount = true;
            options.SignIn.RequireConfirmedEmail = true;
        });
        services.ConfigureApplicationCookie(options =>
        {
            options.SlidingExpiration = true; // Expiration time initially taken from access token
            options.Events.OnCheckSlidingExpiration = async(context)  =>
            {
                if (context.Properties.AllowRefresh == true && context.ShouldRenew) // Renew is true when elapsed time > remaining time
                {
                    var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<CognitoUser>>() as CognitoUserManager<CognitoUser>;

                    var tokens = context.Properties.GetTokens();
                    var idToken = tokens.FirstOrDefault(t => t.Name == OpenIdConnectParameterNames.IdToken);
                    var refreshToken = tokens.FirstOrDefault(t => t.Name == OpenIdConnectParameterNames.RefreshToken);
                    var accessToken = tokens.FirstOrDefault(t => t.Name == OpenIdConnectParameterNames.AccessToken);

                    // Find user and refresh tokens 
                    var email = context.Principal.Claims.First(x => x.Type == "email").Value;
                    
                    var user = await userManager.FindByEmailAsync(email);
                    if (user != null)
                    {
                        // Set session tokens
                        DateTime currentTime = DateTime.UtcNow;
                        // Must be set before start
                        user.SessionTokens = new CognitoUserSession(
                            idToken.Value,
                            accessToken.Value,
                            refreshToken.Value,
                            context.Properties.IssuedUtc.Value.UtcDateTime,
                            context.Properties.ExpiresUtc.Value.UtcDateTime);

                        // Get new tokens
                        var tokenResponse = await user.StartWithRefreshTokenAuthAsync(
                            new InitiateRefreshTokenAuthRequest()
                            {
                                AuthFlowType = AuthFlowType.REFRESH_TOKEN
                            }
                            ).ConfigureAwait(false);

                        // set new token values
                        idToken.Value = tokenResponse.AuthenticationResult.IdToken;
                        refreshToken.Value = tokenResponse.AuthenticationResult.RefreshToken;
                        accessToken.Value = tokenResponse.AuthenticationResult.AccessToken;

                        // update the expiration date
                        context.Properties.IssuedUtc = DateTimeOffset.UtcNow;
                        context.Properties.ExpiresUtc = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(tokenResponse.AuthenticationResult.ExpiresIn);
                        context.Properties.StoreTokens(tokens);

                        // ShouldRenew = true will renew the cookie with updated tokens
                    }
                }
            };
        });
        services.AddRazorPages(options =>
        {
            options.Conventions.AuthorizePage("/Private");
        });
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapRazorPages();
        });
    }
}
