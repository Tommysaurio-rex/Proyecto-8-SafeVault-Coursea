using SafeVault;

namespace SafeVault.Tests;

public class SecurityTests
{
    private readonly SecurityService _security;

    public SecurityTests()
    {
        _security = new SecurityService();
    }

    // ============================================
    // VALIDACIÓN DE USUARIO
    // ============================================

    [Fact]
    public void Username_ShouldRejectSqlInjection()
    {
        var maliciousUsername =
            "' OR '1'='1";

        var result =
            _security.ValidateUsername(
                maliciousUsername);

        Assert.False(result);
    }

    // ============================================
    // XSS
    // ============================================

    [Fact]
    public void Html_ShouldEncodeScript()
    {
        var maliciousInput =
            "<script>alert('XSS')</script>";

        var result =
            _security.SanitizeForHtml(
                maliciousInput);

        Assert.DoesNotContain(
            "<script>",
            result);

        Assert.Contains(
            "&lt;script&gt;",
            result);
    }

    // ============================================
    // PASSWORD HASH
    // ============================================

    [Fact]
    public void Password_ShouldBeHashed()
    {
        var password =
            "Password123!";

        var hash =
            _security.HashPassword(password);

        Assert.NotEqual(
            password,
            hash);

        Assert.True(
            _security.VerifyPassword(
                password,
                hash));
    }

    // ============================================
    // PASSWORD INCORRECTA
    // ============================================

    [Fact]
    public void WrongPassword_ShouldFail()
    {
        var password =
            "Password123!";

        var wrongPassword =
            "WrongPassword!";

        var hash =
            _security.HashPassword(password);

        Assert.False(
            _security.VerifyPassword(
                wrongPassword,
                hash));
    }

    // ============================================
    // EMAIL
    // ============================================

    [Fact]
    public void Email_ShouldRejectInvalidInput()
    {
        var maliciousEmail =
            "<script>alert(1)</script>";

        Assert.False(
            _security.ValidateEmail(
                maliciousEmail));
    }

    // ============================================
    // USERNAME
    // ============================================

    [Theory]
    [InlineData("admin")]
    [InlineData("user123")]
    [InlineData("student_01")]
    public void ValidUsernames_ShouldBeAccepted(
        string username)
    {
        Assert.True(
            _security.ValidateUsername(
                username));
    }

    // ============================================
    // USERNAME MALICIOSO
    // ============================================

    [Theory]
    [InlineData("' OR 1=1 --")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("admin'--")]
    [InlineData("\" OR \"1\"=\"1")]
    public void MaliciousUsernames_ShouldBeRejected(
        string username)
    {
        Assert.False(
            _security.ValidateUsername(
                username));
    }
}