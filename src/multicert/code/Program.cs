using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Connections.Features;

using Microsoft.AspNetCore.Server.Kestrel.Https;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
	options.ListenAnyIP(8443, listenOptions =>
	{
		_ = listenOptions.UseHttps(httpsOptions =>
		{
			httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
			httpsOptions.AllowAnyClientCertificate();
			httpsOptions.TlsClientHelloBytesCallback = ClientHelloCipherSuiteMiddleware.Process;
			httpsOptions.ServerCertificateSelector = (connectionContext, name) =>
			{
				if (connectionContext is null)
				{
					throw new ArgumentNullException(nameof(connectionContext));
				}

				var tlsHandshakeFeature = connectionContext.Features.Get<ITlsHandshakeFeature>();

				// connectionContext.Transport.Input.

				var memoryPoolFeature  = connectionContext.Features.Get<IMemoryPoolFeature >();

				//memoryPoolFeature.MemoryPool.Rent

				// memoryPoolFeature?.MemoryPool

				// For demonstration purposes, we can use a self-signed certificate.
				// In production, you would load a proper certificate from a secure location.
				return null;
			};
		});

	});
});

var app = builder.Build();

app.UseWebSockets();

app.MapGet("/", () => Results.Ok(new
{
	Message = "WebSocket endpoint: wss://localhost:8443/ws",
	ClientCertificateMode = "AllowCertificate"
}));

app.Map("/ws", async context =>
{
	if (!context.WebSockets.IsWebSocketRequest)
	{
		context.Response.StatusCode = StatusCodes.Status400BadRequest;
		await context.Response.WriteAsync("Expected a WebSocket upgrade request.");
		return;
	}

	var clientCertificate = await context.Connection.GetClientCertificateAsync();

	Console.WriteLine("[WS Handshake] Client certificate intercepted:");
	if (clientCertificate is null)
	{
		Console.WriteLine("  No client certificate provided.");
	}
	else
	{
		Console.WriteLine($"  Subject: {clientCertificate.Subject}");
		Console.WriteLine($"  Issuer: {clientCertificate.Issuer}");
		Console.WriteLine($"  Thumbprint: {clientCertificate.Thumbprint}");
		Console.WriteLine($"  NotBefore: {clientCertificate.NotBefore:O}");
		Console.WriteLine($"  NotAfter: {clientCertificate.NotAfter:O}");
	}

	using var webSocket = await context.WebSockets.AcceptWebSocketAsync();

	var certificateSummary = clientCertificate is null
		? "Client certificate: none"
		: $"Client certificate subject: {clientCertificate.Subject}";

	var payload = System.Text.Encoding.UTF8.GetBytes(certificateSummary);
	await webSocket.SendAsync(payload, WebSocketMessageType.Text, endOfMessage: true, CancellationToken.None);

	await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Done", CancellationToken.None);
});

app.Run();
