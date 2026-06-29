using System;
using System.IO;
using System.Runtime.InteropServices;

namespace SkidrowKiller.Services
{
    /// <summary>
    /// Real Authenticode verification via the Windows WinVerifyTrust API.
    ///
    /// This replaces the old "does a certificate table exist in the PE?" heuristic, which malware
    /// trivially defeats by embedding a junk/self-signed cert. WinVerifyTrust actually validates that
    /// (a) the file is signed, (b) the embedded hash matches the file bytes, and (c) the signing
    /// certificate chains to a trusted root. That makes a *valid* signature a strong "trust me" signal
    /// (huge false-positive reducer for legit unsigned-looking-but-signed apps) and a *broken/forged*
    /// signature a strong "this is a ghost" signal.
    ///
    /// Revocation checking is intentionally disabled so a scan never blocks on a network call.
    /// </summary>
    internal static class AuthenticodeVerifier
    {
        public enum SignatureStatus
        {
            Unknown,    // could not be determined (unsupported subject, error)
            NotSigned,  // no signature present
            Valid,      // signed AND trusted AND hash matches
            Invalid     // signed but broken: bad digest, untrusted root, expired, etc. (suspicious)
        }

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x10;

        // Common return codes
        private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
        private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
        private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
        private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
        private const uint TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004;

        public static SignatureStatus Verify(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return SignatureStatus.Unknown;

            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            IntPtr pData = IntPtr.Zero;

            try
            {
                Marshal.StructureToPtr(fileInfo, pFile, false);

                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    pFile = pFile,
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE
                };

                pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
                Marshal.StructureToPtr(data, pData, false);

                uint result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                // Always close the verifier state to release the held context.
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, pData, true);
                WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                return result switch
                {
                    0 => SignatureStatus.Valid,
                    TRUST_E_NOSIGNATURE => SignatureStatus.NotSigned,
                    TRUST_E_SUBJECT_FORM_UNKNOWN => SignatureStatus.Unknown,
                    TRUST_E_PROVIDER_UNKNOWN => SignatureStatus.Unknown,
                    // signed but the signature does not validate / is distrusted → suspicious
                    TRUST_E_EXPLICIT_DISTRUST => SignatureStatus.Invalid,
                    TRUST_E_SUBJECT_NOT_TRUSTED => SignatureStatus.Invalid,
                    _ => SignatureStatus.Invalid
                };
            }
            catch
            {
                return SignatureStatus.Unknown;
            }
            finally
            {
                if (pFile != IntPtr.Zero) Marshal.FreeHGlobal(pFile);
                if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            }
        }
    }
}
