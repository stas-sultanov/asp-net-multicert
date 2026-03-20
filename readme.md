# Kestrel TLS Server Certificate Selection

This demo shows how an ASP.NET web server can offer different server certificates during the TLS handshake.

According to [RFC 8446][rfc_8446], during the TLS handshake the client provides information about which server authentication algorithm it supports.

The location of this information depends on the TLS version used by the client.
- TLS 1.2: within [ClientHello.cipher_suites][rfc_8446_clienthello].
- TLS 1.3: in the [SignatureSchemeList][rfc_8446_signature_scheme_list] extension of ClientHello [Extensions][rfc_8446_extensions].

## How it works

- Kestrel exposes the following APIs:
  - [TlsClientHelloBytesCallback][ms_learn_tlsclienthellobytescallback]<br>fires when `ClientHello` is received from the client and provides raw bytes of the TLS record.
  - [ServerCertificateSelector][ms_learn_servercertificateselector]<br>fires before TLS negotiation completes and returns the certificate to use.
- [TlsClientHelloParser][code_TlsClientHelloParser] parses the TLS record and extracts information from `ClientHello`.

### Flow

1. A method subscribed to [TlsClientHelloBytesCallback][ms_learn_tlsclienthellobytescallback] calls [TryParse][code_TryParse] and stores the parsed [TlsSignatureAlgorithms][code_TlsSignatureAlgorithms] value in [ConnectionContext][ms_learn_ConnectionContext].
2. A method subscribed to [ServerCertificateSelector][ms_learn_servercertificateselector] reads [TlsSignatureAlgorithms][code_TlsSignatureAlgorithms] from [ConnectionContext][ms_learn_ConnectionContext].
3. If the client supports ECDSA, the server returns the ECDSA certificate first. Otherwise, if RSA is supported, it returns the RSA certificate.

## Prerequisites

To run tests on Windows:

- WSL with a Linux distribution
- [.NET 10 SDK][dotnet_10_sdk]
- VS Code with the following extensions:
  - **Remote – WSL** (`ms-vscode-remote.remote-wsl`)
  - **C# Dev Kit** (`ms-dotnettools.csdevkit`)

---

[rfc_8446]: https://www.rfc-editor.org/rfc/rfc8446
[rfc_8446_clienthello]: https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
[rfc_8446_extensions]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2
[rfc_8446_signature_scheme_list]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
[dotnet_10_sdk]: https://dotnet.microsoft.com/download/dotnet/10.0
[ms_learn_tlsclienthellobytescallback]: https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.tlsclienthellobytescallback?view=aspnetcore-10.0
[ms_learn_servercertificateselector]: https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.server.kestrel.https.httpsconnectionadapteroptions.servercertificateselector
[ms_learn_ConnectionContext]: https://learn.microsoft.com/dotnet/api/microsoft.aspnetcore.connections.connectioncontext?view=aspnetcore-10.0

[code_TlsClientHelloParser]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
[code_TlsSignatureAlgorithms]: ./src/System.Utils/code/Net/Security/TlsSignatureAlgorithms.cs

[code_TryParse]: ./src/System.Utils/code/Net/Security/TlsClientHelloParser.cs
