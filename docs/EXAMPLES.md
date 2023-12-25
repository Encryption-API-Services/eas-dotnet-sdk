**Note: Benchmarks are performed on an AMD Ryzen 7 5800H Processor @ 3.20 GHz with 16GB of DDR3** 

### Symmetric
- [AES 256](./docs/PARALLEL.md)

| Library | 50 Encrypts in (s) |
| --- | --- |
| [CAS AES-256](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/Symmetric/AESWrapper.cs) | 00.0068827 (s) |
| [AES C#](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-8.0)| 00.0079577 (s) |
```csharp
AESWrapper aesWrapper = new AESWrapper();
string nonceKey = aesWrapper.GenerateAESNonce();
string key2 = aesWrapper.Aes256Key();
byte[] encrypted = aesWrapper.Aes256EncryptBytes(nonceKey, key2, data);
```


### Signatures 
- ED25519

| Library | 50 Signatures in (s) |
| --- | --- |
| [CAS ED25519](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/Signatures/ED25519Wrapper.cs) | 00.0073306 (s) |
| [NSec Ed25519](https://nsec.rocks/docs/api/nsec.cryptography.signaturealgorithm)| 00.0241969 (s) |
```csharp
ED25519Wrapper ed25519Wrapper = new ED25519Wrapper();
byte[] keyPair = ed25519Wrapper.GetKeyPairBytes();
Ed25519ByteSignatureResult signature = ed25519Wrapper.SignBytes(keyPair, data);
```

| Library | 50 Verifications in (s) |
| --- | --- |
| [CAS ED25519](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/Signatures/ED25519Wrapper.cs) | 00.0091130 (s) |
| [NSec Ed25519](https://nsec.rocks/docs/api/nsec.cryptography.signaturealgorithm)| 00.0273138 (s) |
```csharp
ED25519Wrapper ed25519Wrapper = new ED25519Wrapper();
byte[] keyPair = ed25519Wrapper.GetKeyPairBytes();
Ed25519ByteSignatureResult signature = ed25519Wrapper.SignBytes(keyPair, data);
bool isValid = ed25519Wrapper.VerifyWithPublicKeyBytes(signature.PublicKey, signature.Signature, data);
```


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

- SHA512

| Library | 50 Hashes in (s) |
| --- | --- |
| [CAS SHA512](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/Hashers/SHAWrapper.cs) | 00.0059154 (s) |
| [SHA512 Managed C#](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.sha512managed?view=net-8.0) | 00.0042587 (s) |
```csharp
string toHash = "newShaToHash";
byte[] data = Encoding.UTF8.GetBytes(toHash);
SHAWrapper shaWrapper = new SHAWrapper();
byte[] newSha = shaWrapper.SHA512HashBytes(data);
```

- HMAC

| Library | 50 Hashes in (s) |
| --- | --- |
| [CAS HMAC](https://github.com/Cryptographic-API-Services/cas-dotnet-sdk/blob/main/cas-dotnet-sdk/Hashers/HmacWrapper.cs) | 00.0060037 (s) |
| [HMAC256 Managed C#](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256?view=net-8.0) | 00.0042263 (s) |
```csharp
string toHash = "C#IsASuperDuperLanguage";
string key = "HmacKeyForSigning";
byte[] data = Encoding.UTF8.GetBytes(toHash);
byte[] message = Encoding.UTF8.GetBytes(key);

DateTime start = DateTime.Now;
HmacWrapper hmacWrapper = new HmacWrapper();
byte[] hmacSigned = hmacWrapper.HmacSignBytes(data, message);
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