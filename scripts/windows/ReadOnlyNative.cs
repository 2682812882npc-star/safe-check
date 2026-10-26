// Windows APIs below only query local audit policy and local LSA user rights.
// No policy setters, remote system names, account translation, or token changes.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace BaselineReadOnly
{
    public sealed class QueryRecord
    {
        public string Name;
        public string Status;
        public string Error;
        public uint NativeCode;
        public double Value;
        public uint RawValue;
        public string RawUnit;
        public string Unit;
        public string[] Sids;
    }

    public static class NativeQueries
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct AuditInfo
        {
            public Guid Subcategory;
            public uint Information;
            public Guid Category;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct LsaAttributes
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct LsaString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy([In] Guid[] subcategories,
            uint count, out IntPtr buffer);
        [DllImport("advapi32.dll")]
        private static extern void AuditFree(IntPtr buffer);
        [DllImport("advapi32.dll")]
        private static extern uint LsaOpenPolicy(IntPtr systemName,
            ref LsaAttributes attributes, uint desiredAccess, out IntPtr handle);
        [DllImport("advapi32.dll")]
        private static extern uint LsaEnumerateAccountsWithUserRight(IntPtr handle,
            ref LsaString userRight, out IntPtr buffer, out uint count);
        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint status);
        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr buffer);
        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        private struct Modals0
        {
            public uint MinimumLength;
            public uint MaximumAge;
            public uint MinimumAge;
            public uint ForceLogoff;
            public uint HistoryLength;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Modals3
        {
            public uint Duration;
            public uint ObservationWindow;
            public uint Threshold;
        }
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetUserModalsGet(string serverName, uint level, out IntPtr buffer);
        [DllImport("netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        public static QueryRecord[] QueryLocalAccountPolicy()
        {
            var results = new List<QueryRecord>();
            foreach (uint level in new uint[] { 0, 3 })
            {
                IntPtr buffer = IntPtr.Zero;
                try
                {
                    // NULL server name guarantees a local query, no domain discovery.
                    uint code = NetUserModalsGet(null, level, out buffer);
                    if (code != 0)
                    {
                        string[] names = level == 0
                            ? new string[] { "MinimumPasswordLength", "MaximumPasswordAge", "MinimumPasswordAge", "PasswordHistorySize" }
                            : new string[] { "LockoutDuration", "ResetLockoutCount", "LockoutBadCount" };
                        foreach (string name in names)
                            results.Add(new QueryRecord { Name = name, Status = "Error", NativeCode = code,
                                Error = new Win32Exception((int)code).Message });
                    }
                    else if (level == 0)
                    {
                        var m = (Modals0)Marshal.PtrToStructure(buffer, typeof(Modals0));
                        results.Add(new QueryRecord { Name = "MinimumPasswordLength", Status = "Ok", Value = m.MinimumLength, RawValue = m.MinimumLength, RawUnit = "characters", Unit = "characters" });
                        results.Add(new QueryRecord { Name = "MaximumPasswordAge", Status = "Ok", Value = m.MaximumAge == UInt32.MaxValue ? 0 : m.MaximumAge / 86400.0, RawValue = m.MaximumAge, RawUnit = "seconds", Unit = "days (0=never expires)" });
                        results.Add(new QueryRecord { Name = "MinimumPasswordAge", Status = "Ok", Value = m.MinimumAge / 86400.0, RawValue = m.MinimumAge, RawUnit = "seconds", Unit = "days" });
                        results.Add(new QueryRecord { Name = "PasswordHistorySize", Status = "Ok", Value = m.HistoryLength, RawValue = m.HistoryLength, RawUnit = "count", Unit = "count" });
                    }
                    else
                    {
                        var m = (Modals3)Marshal.PtrToStructure(buffer, typeof(Modals3));
                        results.Add(new QueryRecord { Name = "LockoutDuration", Status = "Ok", Value = m.Duration == UInt32.MaxValue ? 0 : m.Duration / 60.0, RawValue = m.Duration, RawUnit = "seconds", Unit = "minutes (0=no automatic unlock)" });
                        results.Add(new QueryRecord { Name = "ResetLockoutCount", Status = "Ok", Value = m.ObservationWindow / 60.0, RawValue = m.ObservationWindow, RawUnit = "seconds", Unit = "minutes" });
                        results.Add(new QueryRecord { Name = "LockoutBadCount", Status = "Ok", Value = m.Threshold, RawValue = m.Threshold, RawUnit = "count", Unit = "count" });
                    }
                }
                finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
            }
            return results.ToArray();
        }

        public static QueryRecord[] QueryAudits(string[] ids)
        {
            var results = new List<QueryRecord>();
            var guids = new Guid[ids.Length];
            for (int i = 0; i < ids.Length; i++) guids[i] = new Guid(ids[i]);
            IntPtr buffer = IntPtr.Zero;
            try
            {
                if (!AuditQuerySystemPolicy(guids, (uint)guids.Length, out buffer))
                {
                    int code = Marshal.GetLastWin32Error();
                    foreach (string id in ids)
                        results.Add(new QueryRecord { Name = id, Status = "Error",
                            NativeCode = (uint)code, Error = new Win32Exception(code).Message });
                }
                else
                {
                    int size = Marshal.SizeOf(typeof(AuditInfo));
                    for (int i = 0; i < ids.Length; i++)
                    {
                        var row = (AuditInfo)Marshal.PtrToStructure(
                            IntPtr.Add(buffer, i * size), typeof(AuditInfo));
                        if (Array.IndexOf(guids, row.Subcategory) < 0 || (row.Information & ~7u) != 0)
                            throw new InvalidOperationException("Audit policy returned unexpected GUID or flags; no compliance result was inferred.");
                        results.Add(new QueryRecord { Name = row.Subcategory.ToString("B"),
                            Status = "Ok", Value = row.Information, RawValue = row.Information, RawUnit = "native flags", Unit = "native flags" });
                    }
                }
            }
            finally { if (buffer != IntPtr.Zero) AuditFree(buffer); }
            return results.ToArray();
        }

        public static QueryRecord[] QueryRights(string[] rights)
        {
            var results = new List<QueryRecord>();
            var attributes = new LsaAttributes();
            attributes.Length = (uint)Marshal.SizeOf(typeof(LsaAttributes));
            IntPtr handle;
            // POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION: read access only.
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x00000801, out handle);
            if (status != 0)
            {
                uint code = LsaNtStatusToWinError(status);
                foreach (string right in rights)
                    results.Add(new QueryRecord { Name = right, Status = "Error",
                        NativeCode = status, Error = new Win32Exception((int)code).Message });
                return results.ToArray();
            }
            try
            {
                foreach (string right in rights)
                {
                    var str = new LsaString();
                    str.Length = checked((ushort)(right.Length * 2));
                    str.MaximumLength = checked((ushort)(str.Length + 2));
                    str.Buffer = Marshal.StringToHGlobalUni(right);
                    IntPtr buffer = IntPtr.Zero;
                    try
                    {
                        uint count;
                        uint s = LsaEnumerateAccountsWithUserRight(handle, ref str,
                            out buffer, out count);
                        if (s == 0 || s == 0x8000001A)
                        {
                            // STATUS_NO_MORE_ENTRIES is a successful empty assignment.
                            var sids = new List<string>();
                            if (s == 0)
                                for (int i = 0; i < count; i++)
                                {
                                    IntPtr sid = Marshal.ReadIntPtr(buffer, i * IntPtr.Size);
                                    sids.Add(new SecurityIdentifier(sid).Value);
                                }
                            results.Add(new QueryRecord { Name = right, Status = "Ok",
                                NativeCode = s, Sids = sids.ToArray() });
                        }
                        else
                            results.Add(new QueryRecord { Name = right, Status = "Error",
                                NativeCode = s,
                                Error = new Win32Exception((int)LsaNtStatusToWinError(s)).Message });
                    }
                    catch (Exception e)
                    {
                        results.Add(new QueryRecord { Name = right, Status = "Error", Error = e.Message });
                    }
                    finally
                    {
                        if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
                        Marshal.FreeHGlobal(str.Buffer);
                    }
                }
            }
            finally { LsaClose(handle); }
            return results.ToArray();
        }
    }
}
