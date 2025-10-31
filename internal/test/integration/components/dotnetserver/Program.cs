var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
var app = builder.Build();

app.MapGet("/greeting", async (HttpClient httpClient) =>
        {
            var response = await httpClient.GetAsync("https://opentelemetry.io/");
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            return Results.Ok(content);
        });
app.MapGet("/smoke", () => "");

app.Run();
