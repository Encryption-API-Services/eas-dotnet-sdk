﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static CasDotnetSdk.Signatures.ED25519Wrapper;

namespace CasDotnetSdk.Signatures.Linux
{
    internal static class ED25519LinuxWrapper
    {
        [DllImport("performant_encryption.so")]
        public static extern IntPtr get_ed25519_key_pair();
        [DllImport("performant_encryption.so")]
        public static extern Ed25519SignatureStruct sign_with_key_pair(string keyBytes, string dataToSign);
        [DllImport("performant_encryption.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_key_pair(string keyBytes, string signature, string dataToVerify);
        [DllImport("performant_encryption.so")]
        [return: MarshalAs(UnmanagedType.I1)]
        public static extern bool verify_with_public_key(string publicKey, string signature, string dataToVerify);
        [DllImport("performant_encryption.so")]
        public static extern void free_cstring(IntPtr stringToFree);
    }
}
