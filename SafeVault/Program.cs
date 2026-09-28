using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Data.Sqlite;
using SafeVault;

var builder = WebApplication.CreateBuilder(args);

// ============================================
// SERVICIOS
// ============================================

builder.Services.AddSingleton<Database>();
builder.Services.AddSingleton<SecurityService>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/access-denied";
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// ============================================
// BASE DE DATOS
// ============================================

var database = app.Services.GetRequiredService<Database>();
await database.InitializeAsync();

// ============================================
// ARCHIVOS ESTÁTICOS
// ============================================

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// ============================================
// PÁGINA PRINCIPAL
// ============================================

app.MapGet("/", () =>
{
    return Results.Content("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SafeVault</title>
            <meta charset="UTF-8">
        </head>
        <body>
            <h1>SafeVault</h1>

            <h2>Inicio de sesión</h2>

            <form method="post" action="/login">
                <label>Usuario:</label>
                <input name="username" required maxlength="50">

                <br><br>

                <label>Contraseña:</label>
                <input type="password" name="password" required maxlength="100">

                <br><br>

                <button type="submit">Iniciar sesión</button>
            </form>

            <hr>

            <h2>Registro</h2>

            <form method="post" action="/register">
                <label>Usuario:</label>
                <input name="username" required maxlength="50">

                <br><br>

                <label>Email:</label>
                <input type="email" name="email" required maxlength="150">

                <br><br>

                <label>Contraseña:</label>
                <input type="password" name="password" required maxlength="100">

                <br><br>

                <button type="submit">Registrarse</button>
            </form>
        </body>
        </html>
        """, "text/html");
});

// ============================================
// REGISTRO
// ============================================

app.MapPost("/register", async (
    HttpRequest request,
    Database db,
    SecurityService security) =>
{
    var form = await request.ReadFormAsync();

    var username = form["username"].ToString();
    var email = form["email"].ToString();
    var password = form["password"].ToString();

    // VALIDACIÓN DE ENTRADAS
    if (!security.ValidateUsername(username))
        return Results.BadRequest("Usuario inválido.");

    if (!security.ValidateEmail(email))
        return Results.BadRequest("Email inválido.");

    if (!security.ValidatePassword(password))
        return Results.BadRequest(
            "La contraseña debe tener al menos 8 caracteres.");

    // Comprobar si existe
    var existingUser = await db.GetUserByUsernameAsync(username);

    if (existingUser != null)
        return Results.BadRequest("El usuario ya existe.");

    // HASH SEGURO
    var passwordHash = security.HashPassword(password);

    // INSERT PARAMETRIZADO
    await db.CreateUserAsync(
        username,
        email,
        passwordHash,
        "user");

    return Results.Redirect("/");
});

// ============================================
// LOGIN
// ============================================

app.MapPost("/login", async (
    HttpRequest request,
    Database db,
    SecurityService security) =>
{
    var form = await request.ReadFormAsync();

    var username = form["username"].ToString();
    var password = form["password"].ToString();

    if (!security.ValidateUsername(username))
        return Results.Unauthorized();

    var user = await db.GetUserByUsernameAsync(username);

    if (user == null)
        return Results.Unauthorized();

    if (!security.VerifyPassword(password, user.PasswordHash))
        return Results.Unauthorized();

    var claims = new List<System.Security.Claims.Claim>
    {
        new(
            System.Security.Claims.ClaimTypes.Name,
            user.Username),

        new(
            System.Security.Claims.ClaimTypes.Role,
            user.Role)
    };

    var identity = new System.Security.Claims.ClaimsIdentity(
        claims,
        CookieAuthenticationDefaults.AuthenticationScheme);

    var principal =
        new System.Security.Claims.ClaimsPrincipal(identity);

    await request.HttpContext.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        principal);

    return Results.Redirect("/dashboard");
});

// ============================================
// DASHBOARD
// ============================================

app.MapGet("/dashboard", [Authorize] (HttpContext context) =>
{
    var username =
        context.User.Identity?.Name ?? "Usuario";

    return Results.Content($"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Dashboard</title>
        </head>

        <body>
            <h1>Dashboard de SafeVault</h1>

            <p>
                Bienvenido,
                <strong>{System.Net.WebUtility.HtmlEncode(username)}</strong>
            </p>

            <p>
                Has iniciado sesión correctamente.
            </p>

            <a href="/logout">Cerrar sesión</a>
        </body>
        </html>
        """, "text/html");
});

// ============================================
// PANEL ADMINISTRATIVO
// ============================================

app.MapGet(
    "/admin",
    [Authorize(Roles = "admin")]
    (HttpContext context) =>
    {
        var username =
            context.User.Identity?.Name ?? "Administrador";

        return Results.Content($"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Administración</title>
            </head>

            <body>
                <h1>Panel administrativo</h1>

                <p>
                    Bienvenido administrador:
                    <strong>
                        {System.Net.WebUtility.HtmlEncode(username)}
                    </strong>
                </p>

                <p>
                    Esta página solamente puede ser utilizada
                    por usuarios con el rol <strong>admin</strong>.
                </p>

                <a href="/logout">Cerrar sesión</a>
            </body>
            </html>
            """, "text/html");
    });

// ============================================
// LOGOUT
// ============================================

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(
        CookieAuthenticationDefaults.AuthenticationScheme);

    return Results.Redirect("/");
});

// ============================================
// ACCESS DENIED
// ============================================

app.MapGet("/access-denied", () =>
{
    return Results.StatusCode(403);
});

// ============================================
// BUSQUEDA SEGURA
// ============================================

app.MapGet(
    "/search",
    [Authorize]
    async (
        string? username,
        Database db,
        SecurityService security) =>
    {
        if (string.IsNullOrWhiteSpace(username))
            return Results.BadRequest("Debe proporcionar un usuario.");

        if (!security.ValidateUsername(username))
            return Results.BadRequest("Entrada inválida.");

        var user = await db.GetUserByUsernameAsync(username);

        if (user == null)
            return Results.NotFound();

        return Results.Ok(new
        {
            user.Username,
            user.Email,
            user.Role
        });
    });

app.Run();

public partial class Program
{
}