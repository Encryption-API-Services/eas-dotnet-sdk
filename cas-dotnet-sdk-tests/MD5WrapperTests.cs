﻿using CasDotnetSdk.Hashers;
using CasDotnetSdk.Helpers;
using System.Runtime.InteropServices;
using Xunit;

namespace CasDotnetSdkTests.Tests
{
    public class MD5WrapperTests
    {
        private MD5Wrapper _md5Wrapper { get; set; }
        private readonly OperatingSystemDeterminator _operatingSystem;
        public MD5WrapperTests()
        {
            _md5Wrapper = new MD5Wrapper();
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void CreateHash()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToHash = "HashThisData";
                string hashed = this._md5Wrapper.Hash(dataToHash);
                Assert.NotEmpty(hashed);
                Assert.NotNull(hashed);
                Assert.NotEqual(dataToHash, hashed);
            }
        }

        [Fact]
        public async Task VerifyHash()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                string dataToHash = "HashThisData";
                string hashed = this._md5Wrapper.Hash(dataToHash);
                Assert.NotEmpty(hashed);
                Assert.NotNull(hashed);
                Assert.NotEqual(dataToHash, hashed);
                Assert.True(this._md5Wrapper.Verify(hashed, dataToHash));
            }
        }
    }
}