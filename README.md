# SafeVault

Proyecto Capstone de seguridad de aplicaciones.

# Descripción

SafeVault es una aplicación web diseñada para demostrar prácticas
de desarrollo seguro, incluyendo validación de entradas,
prevención de SQL Injection, prevención de XSS,
autenticación y autorización basada en roles.

# Tecnologías

- ASP.NET Core
- C#
- SQLite
- BCrypt
- xUnit
- GitHub

# Seguridad implementada

# 1 Validación de entradas

Los nombres de usuario, correos electrónicos y contraseñas
son validados antes de ser procesados.

# 2 Prevención de SQL Injection

Las consultas SQL utilizan parámetros en lugar de concatenación
de cadenas.

# 3 Prevención de XSS

Las entradas que se muestran en HTML son codificadas utilizando
HtmlEncode.

# 4 Autenticación

Las contraseñas no se almacenan en texto plano.
Se utiliza BCrypt para generar hashes de contraseña.

# 5 Autorización

SafeVault utiliza roles:

- user
- admin

El panel administrativo está protegido mediante autorización
basada en roles.

# 6 Pruebas

El proyecto contiene pruebas para:

- SQL Injection
- XSS
- Hash de contraseñas
- Contraseñas incorrectas
- Validación de usuarios
- Validación de correos

# Usuario administrador de demostración

Usuario:

admin

Contraseña:

Admin123!

Este usuario existe únicamente para realizar pruebas del proyecto.

# Ejecución

Restaurar paquetes:

dotnet restore

Compilar:

dotnet build

Ejecutar pruebas:

dotnet test

Ejecutar aplicación:

dotnet run --project SafeVault