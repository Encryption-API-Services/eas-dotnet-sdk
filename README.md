# cas-dotnet-sdk

## Consuming Library Documentation
**Note: All work is experimental and we understand benchmarks might not be the most optimal however we feel that large modern day microservices architectures utilizing multiple languages will benefit from a standardized subset of libraries.**

This C# nuget package is dependent on our Rust layer that contains methods to run industry standard cryptographic operations sequentially, on threads, and the thread pool.
[cas-core-lib](https://github.com/Crytographic-API-Services/cas-core-lib)

## Examples
**Note: Benchmarks are performed on an AMD Ryzen 7 5800H Processor @ 3.20 GHz with 16GB of DDR3** 

### Hashers
- SHA256

| Library | 50 Hashes in (s) |
| --- | --- |
| [CAS SHA256](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/Hashers/SHAWrapper.cs) | 00.0061313 (s) |
| [SHA256 Managed C#](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha256managed?view=net-8.0) | 00.0039384 (s) |
```csharp
string toHash = "newShaToHash";
byte[] data = Encoding.UTF8.GetBytes(toHash);
SHAWrapper shaWrapper = new SHAWrapper();
byte[] newSha = shaWrapper.SHA256HashBytes(data);
```

### Password Hashers
- Argon2
  
| Library | 50 Password Hashes in (s) |
| --- | --- |
| [CAS Argon2](https://github.com/Crytographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/PasswordHashers/Argon2Wrappper.cs) | 00.4824323 (s) |
| [Isopoh.Cryptography.Argon2](https://github.com/mheyman/Isopoh.Cryptography.Argon2) | 26.1985829 (s) |
```csharp
Argon2Wrappper argon2Wrapper = new Argon2Wrappper();
string password = "DoNotDoThisWithMe!@#";
string hashed = argon2Wrapper.HashPassword(password);
```

- SCrypt
  
| Library | 50 Password Hashes in (s) |
| --- | --- |
| [CAS SCrypt](https://github.com/Crytographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/PasswordHashers/Argon2Wrappper.cs) | 03.5280257 (s) |
| [SCrypt.NET](https://github.com/viniciuschiele/scrypt) | 02.4595297 (s) |
```csharp
SCryptWrapper scrypt = new SCryptWrapper();
string password = "SCryptPasswordHash!@#$";
string hashed = scrypt.HashPassword(password);
```

- BCrypt
  
| Library | 50 Password Hashes in (s) |
| --- | --- |
| [CAS BCrypt](https://github.com/Crytographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/PasswordHashers/BcryptWrapper.cs) | 11.5030224 (s) |
| [BCrypt.Net-Core](https://github.com/neoKushan/BCrypt.Net-Core) | 03.3583425 (s) |
```csharp
BcryptWrapper bcrypt = new BcryptWrapper();
string password = "BCryptPasswordHasher!@#$%";
string hashed = bcrypt.HashPassword(password);
```
