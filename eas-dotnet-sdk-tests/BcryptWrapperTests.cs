﻿using EasDotnetSdk.Helpers;
using EasDotnetSdk.PasswordHash;
using System.Runtime.InteropServices;
using Xunit;

namespace EasDotnetSdk.Tests
{
    public class BcryptWrapperTests
    {
        private BcryptWrapper _cryptWrapper { get; set; }
        private readonly OperatingSystemDeterminator _operatingSystem;
        private string _testPassword { get; set; }

        public BcryptWrapperTests()
        {
            this._cryptWrapper = new BcryptWrapper();
            this._testPassword = "testPassword";
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [Fact]
        public void HashPassword()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                IntPtr hashedPasswordPtr = this._cryptWrapper.HashPassword(this._testPassword);
                string hashedPassword = Marshal.PtrToStringUTF8(hashedPasswordPtr);
                BcryptWrapper.free_cstring(hashedPasswordPtr);
                Assert.NotEqual(hashedPassword, this._testPassword);
            }
        }

        [Fact]
        public async Task Verify()
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            else
            {
                IntPtr hashedPasswordPtr = this._cryptWrapper.HashPassword(this._testPassword);
                string hashedPassword = Marshal.PtrToStringUTF8(hashedPasswordPtr);
                BcryptWrapper.free_cstring(hashedPasswordPtr);
                Assert.True(this._cryptWrapper.Verify(hashedPassword, this._testPassword));
            }
        }
    }
}
