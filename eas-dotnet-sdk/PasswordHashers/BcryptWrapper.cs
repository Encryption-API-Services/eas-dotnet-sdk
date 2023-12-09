﻿using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class BcryptWrapper
    {
        private readonly OperatingSystemDeterminator _operatingSystem;
        public BcryptWrapper()
        {
            this._operatingSystem = new OperatingSystemDeterminator();
        }

        [DllImport("performant_encryption.dll")]
        private static extern IntPtr bcrypt_hash(string passToHash);

        [DllImport("performant_encryption.dll")]
        [return: MarshalAs(UnmanagedType.I1)]
        private static extern bool bcrypt_verify(string password, string hash);
        [DllImport("performant_encryption.dll")]
        public static extern void free_cstring(IntPtr stringToFree);

        public string HashPassword(string passwordToHash)
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            IntPtr hashedPtr = bcrypt_hash(passwordToHash);
            string hashed = Marshal.PtrToStringAnsi(hashedPtr);
            BcryptWrapper.free_cstring(hashedPtr);
            return hashed;
        }
        public bool Verify(string hashedPassword, string unhashed)
        {
            OSPlatform platform = this._operatingSystem.GetOperatingSystem();
            if (platform == OSPlatform.Linux)
            {
                throw new NotImplementedException("Linux version not yet supported");
            }
            return bcrypt_verify(unhashed, hashedPassword);
        }
    }
}