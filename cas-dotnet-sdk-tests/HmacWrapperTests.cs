﻿using CasDotnetSdk.Hashers;
using CasDotnetSdk.Helpers;
using System.Runtime.InteropServices;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class HmacWrapperTests
    {
        private HmacWrapper _hmacWrapper { get; set; }
        private readonly OperatingSystemDeterminator _operatingSystem;
        public HmacWrapperTests()
        {
            this._hmacWrapper = new HmacWrapper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void HmacSign()
        {
            string key = "HmacKey";
            string message = "message to sign";
            string signature = this._hmacWrapper.HmacSign(key, message);
            Assert.NotNull(signature);
            Assert.NotEqual(message, signature);
        }

        [Fact]
        public void HmacVerify()
        {
            string key = "HmacKey";
            string message = "message to sign";
            string signature = this._hmacWrapper.HmacSign(key, message);
            bool isValid = this._hmacWrapper.HmacVerify(key, message, signature);
            Assert.Equal(true, isValid);
        }
    }
}