﻿using CasDotnetSdk.Http;
using CasDotnetSdk.PasswordHashers.Linux;
using CasDotnetSdk.PasswordHashers.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.PasswordHashers
{
    public class SCryptWrapper : IPasswordHasherBase
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;

        /// <summary>
        /// A wrapper class that uses the SCrypt algorithm to hash passwords.
        /// </summary>
        public SCryptWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

        /// <summary>
        /// Hashes a password using the SCrypt algorithm.
        /// </summary>
        /// <param name="passToHash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public string HashPassword(string passToHash)
        {
            if (string.IsNullOrEmpty(passToHash))
            {
                throw new Exception("Please provide a password to hash");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr hashedPtr = SCryptLinuxWrapper.scrypt_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SCryptLinuxWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SCryptWrapper));
                return hashed;
            }
            else
            {
                IntPtr hashedPtr = SCryptWindowsWrapper.scrypt_hash(passToHash);
                string hashed = Marshal.PtrToStringAnsi(hashedPtr);
                SCryptWindowsWrapper.free_cstring(hashedPtr);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SCryptWrapper));
                return hashed;
            }
        }

        public string[] HashPasswordsThread(string[] passwordsToHash)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Verifies an unhashed password against a hashed password using the SCrypt algorithm.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool Verify(string password, string hash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            {
                throw new Exception("Please provide a password and a hash to verify");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                bool result = SCryptLinuxWrapper.scrypt_verify(password, hash);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SCryptWrapper));
                return result;
            }
            else
            {

                bool result = SCryptWindowsWrapper.scrypt_verify(password, hash);
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(SCryptWrapper));
                return result;
            }
        }

        public bool VerifyPasswordThread(string hashedPasswrod, string password)
        {
            throw new NotImplementedException();
        }
    }
}