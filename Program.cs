using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorization();

// Load certificate from file with private key for decryption
var certPath = Path.Combine(builder.Environment.ContentRootPath, "Secrets", "vraa_api_manager.pfx");
var certificate = new X509Certificate2(certPath, string.Empty, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = WsFederationDefaults.AuthenticationScheme;
})
.AddCookie()
.AddWsFederation(options =>
{
    options.MetadataAddress = "https://vpmtest.vraa.gov.lv/LVP.STS/FederationMetadata/2007-06/FederationMetadata.xml";
    options.Wtrealm = "urn:bir-test:ptac.gov.lv";
    options.RequireHttpsMetadata = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new X509SecurityKey(certificate),
        TokenDecryptionKey = new X509SecurityKey(certificate)
    };

    // Handle token validation
    options.Events = new WsFederationEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            // Log the original wreply URL
            Console.WriteLine($"Original wreply URL: {context.ProtocolMessage.Wreply}");
            return Task.CompletedTask;
        },
        OnSecurityTokenReceived = context =>
        {
            // Log the token receipt
            Console.WriteLine("Security token received. Raw token:");
            Console.WriteLine(context.ProtocolMessage.GetToken());
            return Task.CompletedTask;
        },
        OnSecurityTokenValidated = context =>
        {
            var identity = context.Principal?.Identity as ClaimsIdentity;
            if (identity != null)
            {
                Console.WriteLine("Token validated. Claims:");
                foreach (var claim in identity.Claims)
                {
                    Console.WriteLine($"Claim Type: {claim.Type}, Value: {claim.Value}");
                }
            }
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($"Authentication failed: {context.Exception}");
            return Task.CompletedTask;
        }
    };
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Test endpoint that requires authentication
app.MapGet("/callback", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var claims = context.User.Claims.Select(c => new { c.Type, c.Value });
        return Results.Ok(new { 
            message = "Authenticated!",
            claims = claims,
            identityProvider = context.User.FindFirst("http://schemas.microsoft.com/identity/claims/identityprovider")?.Value
        });
    }
    return Results.Unauthorized();
}).RequireAuthorization();

// Login endpoint
app.MapGet("/login", () => Results.Challenge(
    new AuthenticationProperties { 
        RedirectUri = "/callback",
        IsPersistent = true
    },
    new[] { WsFederationDefaults.AuthenticationScheme }));

app.Run();
