﻿using CasDotnetSdk.Sponges.Types;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Sponges.Linux
{
    internal static class AsconLinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern IntPtr ascon_128_key();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern IntPtr ascon_128_nonce();

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128EncryptResultStruct ascon_128_encrypt(string nonce, string key, byte[] toEncrypt, int toEncryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Ascon128DecryptResultStruct ascon_128_decrypt(string nonce, string key, byte[] toDecrypt, int toDecryptLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_cstring(IntPtr stringToFree);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern void free_bytes(IntPtr bytesToFree);
    }
}
