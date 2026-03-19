# Kestrel TLS Server Certificate Selection

Demonstrates how an ASP.NET Core / Kestrel HTTPS server can select the right TLS server certificate at handshake time based on the cipher suites the client offers in its TLS `ClientHello` message.

Because cipher suites encode the required server authentication algorithm (RSA or ECDSA), the server can inspect the `ClientHello` before the handshake completes and present the matching certificate — without SNI and without any client-side configuration beyond the normal TLS negotiation.

## How it works

1. Kestrel exposes a `TlsClientHelloBytesCallback` hook that fires before the TLS handshake completes.
2. `TlsClientHelloParser` parses the raw `ClientHello` bytes and derives the set of server-authentication signature algorithms (`TlsSignatureAlgorithms`) implied by the offered TLS 1.2 cipher suites, or by the `signature_algorithms` extension for TLS 1.3.
3. The result is stored on the `ConnectionContext`.
4. Kestrel's `ServerCertificateSelector` callback reads it and returns the ECDsa or RSA certificate accordingly.

## Folder and file structure

```bash
asp-net-multicert/
├── MultiCert.slnx                          Solution file
│
├── src/
│   └── System.Utils/                       Library project (net10.0)
│       ├── System.Utils.csproj
│       └── code/
│           ├── Buffers/
│           │   └── SequenceReaderAdvanceExtensions.cs   SequenceReader helpers for parsing binary data
│           └── Net/Security/
│               ├── TlsClientHelloParseErrorCode.cs     Error codes returned by TlsClientHelloParser
│               ├── TlsClientHelloParser.cs             Parses a TLS ClientHello and derives TlsSignatureAlgorithms
│               ├── TlsSignatureAlgorithms.cs           [Flags] enum: None | RSA | ECDSA
│               └── TlsSignatureScheme.cs               RFC 8446 §4.2.3 SignatureScheme values (internal)
│
└── tests/
    └── System.Utils.Tests/                 MSTest project (net10.0, linux only)
        ├── System.Utils.Tests.csproj
        └── code/
            ├── IntegrationTests/
            │   └── CipherSuitesIntegrationTests.cs     End-to-end TLS handshake tests
            └── Utils/
                ├── CertificateHelper.cs                Creates self-signed ECDsa / RSA certificates
                ├── TestServer.cs                       In-process Kestrel HTTPS server used by tests
                └── TlsHelper.cs                        Shared TLS helpers
```

### Key types

| Type | Project | Purpose |
|---|---|---|
| `TlsClientHelloParser` | `System.Utils` | Parses raw `ClientHello` bytes; returns `TlsSignatureAlgorithms` |
| `TlsSignatureAlgorithms` | `System.Utils` | Flags enum indicating RSA and/or ECDSA support |
| `TlsClientHelloParseErrorCode` | `System.Utils` | Structured error codes for parse failures |
| `TestServer` | `System.Utils.Tests` | Kestrel server wired with the parser and certificate selector |
| `CertificateHelper` | `System.Utils.Tests` | Generates short-lived self-signed certificates for tests |
| `CipherSuitesIntegrationTests` | `System.Utils.Tests` | MSTest integration tests verifying certificate selection |

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Linux (the tests and `TestServer` are decorated with `[SupportedOSPlatform("linux")]` because `CipherSuitesPolicy` is only supported on Linux)
- VS Code with the following extensions:
  - **Remote – WSL** (`ms-vscode-remote.remote-wsl`)
  - **C# Dev Kit** (`ms-dotnettools.csdevkit`)

## Running the tests in VS Code via Remote – WSL

1. **Open a WSL window**

   Open the VS Code Command Palette (`Ctrl+Shift+P`) and run:
   ```
   Remote-WSL: Open Folder in WSL...
   ```
   Navigate to and open the `asp-net-multicert` folder.

2. **Restore dependencies** (VS Code usually does this automatically; if not, open a terminal inside WSL and run):
   ```bash
   dotnet restore
   ```

3. **Run all tests from the terminal**
   ```bash
   dotnet test tests/System.Utils.Tests/System.Utils.Tests.csproj
   ```

4. **Run tests from the Test Explorer UI**

   - Open the **Testing** panel from the Activity Bar (flask icon).
   - VS Code will discover all `[TestMethod]` methods automatically.
   - Click **Run All Tests** or run individual tests by clicking the play button next to them.

5. **Run a single test from the terminal**
   ```bash
   dotnet test tests/System.Utils.Tests/System.Utils.Tests.csproj \
     --filter "FullyQualifiedName~Server_Present_ECDSA_When_Client_Offers_Tls12_CipherSuite_ECDSA"
   ```

> **Note:** The integration tests start a real Kestrel server on a loopback interface using an OS-assigned port (`port 0`), perform a full TLS handshake, and verify which certificate was presented. They require no external infrastructure.
