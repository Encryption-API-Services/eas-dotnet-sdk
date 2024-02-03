﻿using CasDotnetSdk.DigitalSignature;
using CasDotnetSdk.DigitalSignature.Types;
using System.Text;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class DigitalSignatureTests
    {
        private readonly DigitalSignatureWrapper _digitalSignatureWrapper;

        public DigitalSignatureTests()
        {
            this._digitalSignatureWrapper = new DigitalSignatureWrapper();
        }

        [Fact]
        public void SHA512RSA4096DigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            IDigitalSignature digitalSignature = DigitalSignatureFactory.GetRSA(DigitalSignatureRSAType.SHA512ARSA);
            SHARSADigitalSignatureResult signature = digitalSignature.CreateRsa(4096, dataToSign);
            Assert.NotNull(signature.PublicKey);
            Assert.NotNull(signature.PrivateKey);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void SHA512RSA2048DigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WelcomeHomeToSigningData");
            IDigitalSignature digitalSignature = DigitalSignatureFactory.GetRSA(DigitalSignatureRSAType.SHA512ARSA);
            SHARSADigitalSignatureResult signature = digitalSignature.CreateRsa(2048, dataToSign);
            bool result = digitalSignature.VerifyRsa(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA512ED25519DigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            SHAED25519DalekDigitialSignatureResult result = this._digitalSignatureWrapper.SHA512ED25519DigitalSignature(dataToSign);
            Assert.NotEmpty(result.PublicKey);
            Assert.NotEmpty(result.Signature);
        }

        [Fact]
        public void SHA512ED25519DigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("ThisIsTheTestingDataToSign");
            SHAED25519DalekDigitialSignatureResult result = this._digitalSignatureWrapper.SHA512ED25519DigitalSignature(dataToSign);
            bool result2 = this._digitalSignatureWrapper.SHA512ED25519DigitalSignatureVerify(result.PublicKey, dataToSign, result.Signature);
            Assert.True(result2);
        }

        [Fact]
        public void SHA256RSADigitalSignature()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.GetRSA(DigitalSignatureRSAType.SHA256RSA);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsa(4096, dataToSign);
            Assert.NotNull(signature.PublicKey);
            Assert.NotNull(signature.PrivateKey);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void SHA256RSADigitalSignatureVerify()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.GetRSA(DigitalSignatureRSAType.SHA256RSA);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsa(4096, dataToSign);
            bool result = wrapper.VerifyRsa(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA256RSADigitalSignatureVerifyFail()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("SigningDataWithSHA256");
            IDigitalSignature wrapper = DigitalSignatureFactory.GetRSA(DigitalSignatureRSAType.SHA256RSA);
            SHARSADigitalSignatureResult signature = wrapper.CreateRsa(4096, dataToSign);
            dataToSign = Encoding.UTF8.GetBytes("NOtTheSameData");
            bool result = wrapper.VerifyRsa(signature.PublicKey, dataToSign, signature.Signature);
            Assert.False(result);
        }

        [Fact]
        public void SHA256ED25519DalekDigitalSiganture()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            SHAED25519DalekDigitialSignatureResult signature = this._digitalSignatureWrapper.SHA256ED25519DigitialSignature(dataToSign);
            Assert.NotEmpty(signature.PublicKey);
            Assert.NotEmpty(signature.Signature);
        }

        [Fact]
        public void SHA256ED25519DalekVerifyPass()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            SHAED25519DalekDigitialSignatureResult signature = this._digitalSignatureWrapper.SHA256ED25519DigitialSignature(dataToSign);
            bool result = this._digitalSignatureWrapper.SHA256ED25519DigitialSignatureVerify(signature.PublicKey, dataToSign, signature.Signature);
            Assert.True(result);
        }

        [Fact]
        public void SHA256ED25519DalekVerifyFail()
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes("WatchMyStreamAndLearnWIthMe");
            SHAED25519DalekDigitialSignatureResult signature = this._digitalSignatureWrapper.SHA256ED25519DigitialSignature(dataToSign);
            dataToSign = Encoding.UTF8.GetBytes("NotTheSameStuff");
            bool result = this._digitalSignatureWrapper.SHA256ED25519DigitialSignatureVerify(signature.PublicKey, dataToSign, signature.Signature);
            Assert.False(result);
        }
    }
}
