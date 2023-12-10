﻿using EasDotnetSdk.Asymmetric;
using EasDotnetSdk.Helpers;
using System.Runtime.InteropServices;
using Xunit;
using static EasDotnetSdk.Asymmetric.RSAWrapper;

namespace EasDotnetSdk.Tests
{
    public class RSAWrapperTests
    {
        private readonly RSAWrapper _RSAWrapper;
        private readonly RsaKeyPairResult _encryptDecryptKeyPair;
        private readonly OperatingSystemDeterminator _operatingSystem;
        public RSAWrapperTests()
        {
            this._RSAWrapper = new RSAWrapper();
            this._encryptDecryptKeyPair = this._RSAWrapper.GetKeyPair(4096);
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void CreateKeyPair()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                RsaKeyPairResult keyPair = this._RSAWrapper.GetKeyPair(4096);
                Assert.NotNull(keyPair.PublicKey);
                Assert.NotNull(keyPair.PrivateKey);
            }
        }

        [Fact]
        public void RsaEncrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToEncrypt = "EncryptingStuffIsFun";
                string encrypted = this._RSAWrapper.RsaEncrypt(this._encryptDecryptKeyPair.PublicKey, dataToEncrypt);
                Assert.NotEqual(dataToEncrypt, encrypted);
            }
        }

        [Fact]
        public void RsaDecrypt()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToEncrypt = "EncryptingStuffIsFun";
                string encrypted = this._RSAWrapper.RsaEncrypt(this._encryptDecryptKeyPair.PublicKey, dataToEncrypt);
                string decrypted = this._RSAWrapper.RsaDecrypt(this._encryptDecryptKeyPair.PrivateKey, encrypted);
                Assert.Equal(dataToEncrypt, decrypted);
            }
        }

        [Fact]
        public async void RsaSign()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToSign = "Sign This Data For Me";
                RsaSignResult result = this._RSAWrapper.RsaSign(dataToSign, 4096);
                Assert.NotNull(result.PublicKey);
                Assert.NotNull(result.Signature);
            }
        }

        [Fact]
        public async void RsaVerify()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToSign = "Data That Needs To Be Verified";
                RsaSignResult result = this._RSAWrapper.RsaSign(dataToSign, 4096);
                bool isValid = this._RSAWrapper.RsaVerify(result.PublicKey, dataToSign, result.Signature);
                Assert.Equal(true, isValid);
            }
        }

        [Fact]
        public async void RsaSignWithKey()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToSign = "This data needs to be signed now";
                RsaKeyPairResult keyPair = this._RSAWrapper.GetKeyPair(2048);
                string signature = this._RSAWrapper.RsaSignWithKey(keyPair.PrivateKey, dataToSign);
                Assert.NotNull(signature);
                Assert.NotEqual(dataToSign, signature);
            }
        }
    }
}