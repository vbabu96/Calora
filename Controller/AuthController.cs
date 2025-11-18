using Calora.DTOs;
using Calora.Services;

namespace Calora.Controller;

public static class AuthController
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        var authGroup = app.MapGroup("/api/auth").WithTags("Authentication");

        authGroup.MapPost("/register", Register).WithName("Register").WithOpenApi();
        authGroup.MapPost("/login", Login).WithName("Login").WithOpenApi();
    }

    private static async Task<IResult> Register(
        RegisterRequest request,
        IAuthService authService)
    {
        try
        {
            var response = await authService.RegisterAsync(request);
            return Results.Ok(response);
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            return Results.Problem(
                detail: ex.Message,
                statusCode: StatusCodes.Status500InternalServerError
            );
        }
    }

    private static async Task<IResult> Login(
        LoginRequest request,
        IAuthService authService)
    {
        try
        {
            var response = await authService.LoginAsync(request);
            return Results.Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Results.Unauthorized();
        }
        catch (Exception ex)
        {
            return Results.Problem(
                detail: ex.Message,
                statusCode: StatusCodes.Status500InternalServerError
            );
        }
    }
}