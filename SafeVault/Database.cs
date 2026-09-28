using Microsoft.Data.Sqlite;

namespace SafeVault;

public class Database
{
    private readonly string _connectionString;

    public Database()
    {
        _connectionString =
            "Data Source=safevault.db";
    }

    // ============================================
    // CREAR BASE DE DATOS
    // ============================================

    public async Task InitializeAsync()
    {
        await using var connection =
            new SqliteConnection(_connectionString);

        await connection.OpenAsync();

        var command = connection.CreateCommand();

        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users
            (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL,
                PasswordHash TEXT NOT NULL,
                Role TEXT NOT NULL
            );
            """;

        await command.ExecuteNonQueryAsync();

        // Crear usuario administrador de prueba.
        var admin = await GetUserByUsernameAsync("admin");

        if (admin == null)
        {
            var security = new SecurityService();

            await CreateUserAsync(
                "admin",
                "admin@safevault.local",
                security.HashPassword("Admin123!"),
                "admin");
        }
    }

    // ============================================
    // OBTENER USUARIO
    // ============================================

    public async Task<User?> GetUserByUsernameAsync(
        string username)
    {
        await using var connection =
            new SqliteConnection(_connectionString);

        await connection.OpenAsync();

        var command = connection.CreateCommand();

        // ==========================================
        // CONSULTA PARAMETRIZADA
        // ==========================================

        command.CommandText = """
            SELECT
                Id,
                Username,
                Email,
                PasswordHash,
                Role
            FROM Users
            WHERE Username = $username;
            """;

        command.Parameters.AddWithValue(
            "$username",
            username);

        await using var reader =
            await command.ExecuteReaderAsync();

        if (!await reader.ReadAsync())
            return null;

        return new User
        {
            Id = reader.GetInt32(0),
            Username = reader.GetString(1),
            Email = reader.GetString(2),
            PasswordHash = reader.GetString(3),
            Role = reader.GetString(4)
        };
    }

    // ============================================
    // CREAR USUARIO
    // ============================================

    public async Task CreateUserAsync(
        string username,
        string email,
        string passwordHash,
        string role)
    {
        await using var connection =
            new SqliteConnection(_connectionString);

        await connection.OpenAsync();

        var command = connection.CreateCommand();

        // ==========================================
        // INSERT PARAMETRIZADO
        // ==========================================

        command.CommandText = """
            INSERT INTO Users
            (
                Username,
                Email,
                PasswordHash,
                Role
            )
            VALUES
            (
                $username,
                $email,
                $passwordHash,
                $role
            );
            """;

        command.Parameters.AddWithValue(
            "$username",
            username);

        command.Parameters.AddWithValue(
            "$email",
            email);

        command.Parameters.AddWithValue(
            "$passwordHash",
            passwordHash);

        command.Parameters.AddWithValue(
            "$role",
            role);

        await command.ExecuteNonQueryAsync();
    }
}