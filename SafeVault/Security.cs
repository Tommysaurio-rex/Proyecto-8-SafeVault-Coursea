using System.Text.RegularExpressions;

namespace SafeVault;

public class SecurityService
{
    // ============================================
    // VALIDACIÓN DE USUARIO
    // ============================================

    public bool ValidateUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;

        if (username.Length > 50)
            return false;

        // Solo letras, números, guion y underscore.
        return Regex.IsMatch(
            username,
            @"^[a-zA-Z0-9_-]+$");
    }

    // ============================================
    // VALIDACIÓN DE EMAIL
    // ============================================

    public bool ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        if (email.Length > 150)
            return false;

        return Regex.IsMatch(
            email,
            @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
    }

    // ============================================
    // VALIDACIÓN DE CONTRASEÑA
    // ============================================

    public bool ValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            return false;

        return password.Length >= 8 &&
               password.Length <= 100;
    }

    // ============================================
    // HASH DE CONTRASEÑA
    // ============================================

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password);
    }

    // ============================================
    // VERIFICACIÓN DE CONTRASEÑA
    // ============================================

    public bool VerifyPassword(
        string password,
        string passwordHash)
    {
        return BCrypt.Net.BCrypt.Verify(
            password,
            passwordHash);
    }

    // ============================================
    // ESCAPE PARA HTML
    // ============================================

    public string SanitizeForHtml(string input)
    {
        return System.Net.WebUtility.HtmlEncode(input);
    }
}