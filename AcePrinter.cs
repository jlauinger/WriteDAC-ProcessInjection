using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace ProcInject
{

    public static class AcePrinter
    {
        // (bits, name) in precedence order. GENERIC_READ must come before
        // GENERIC_WRITE/EXECUTE because it overlaps their bits.
        private static readonly (uint Bits, string Name)[] MaskNames =
        {
            (0x0010_0000, "SYNCHRONIZE"),
            (0x0008_0000, "WRITE_OWNER"),
            (0x0004_0000, "WRITE_DAC"),
            (0x0002_0000, "READ_CONTROL"),
            (0x0001_0000, "DELETE"),
            (0x0000_1000, "PROCESS_QUERY_LIMITED_INFORMATION"),
            (0x0000_0800, "PROCESS_SUSPEND_RESUME"),
            (0x0000_0400, "PROCESS_QUERY_INFORMATION"),
            (0x0000_0200, "PROCESS_SET_INFORMATION"),
            (0x0000_0100, "PROCESS_SET_QUOTA"),
            (0x0000_0080, "PROCESS_CREATE_PROCESS"),
            (0x0000_0040, "PROCESS_DUP_HANDLE"),
            (0x0000_0020, "PROCESS_VM_WRITE"),
            (0x0000_0010, "PROCESS_VM_READ"),
            (0x0000_0008, "PROCESS_VM_OPERATION"),
            (0x0000_0004, "PROCESS_SET_SESSIONID"),
            (0x0000_0002, "PROCESS_CREATE_THREAD"),
            (0x0000_0001, "PROCESS_TERMINATE"),
        };

        public static string Print(CommonAce ace)
        {
            if (ace is null) throw new ArgumentNullException(nameof(ace));

            var lines = new List<string>
            {
                "    Type:        " + FormatAceType(ace.AceType),
                "    Flags:       " + FormatFlags(ace.AceFlags),
                "    SID:         " + (ace.SecurityIdentifier?.ToString() ?? "(none)"),
                "    Account:     " + ToAccountName(ace.SecurityIdentifier),
                "    Permissions: " + FormatMask(ace.AccessMask),
            };

            int width = lines.Max(l => l.Length);
            var sb = new StringBuilder();
            foreach (string line in lines)
                sb.AppendLine(line);
            return sb.ToString();
        }

        private static string ToAccountName(SecurityIdentifier? sid)
        {
            if (sid is null) return "(none)";
            try
            {
                return sid.Translate(typeof(NTAccount)).ToString();
            }
            catch (Exception ex)
            {
                return $"{sid}  (name unavailable: {ex.Message})";
            }
        }

        private static string FormatAceType(AceType type) => type switch
        {
            AceType.AccessAllowed => "Allow (AccessAllowedAceType)",
            AceType.AccessDenied => "Deny (AccessDeniedAceType)",
            AceType.SystemAudit => "Audit (SystemAuditAceType)",
            _ => type.ToString(),
        };

        private static string FormatFlags(AceFlags flags)
        {
            if (flags == AceFlags.None) return "(none)";
            var parts = new List<string>();
            if (flags.HasFlag(AceFlags.ContainerInherit)) parts.Add("CI (ContainerInherit)");
            if (flags.HasFlag(AceFlags.InheritOnly)) parts.Add("IO (InheritOnly)");
            if (flags.HasFlag(AceFlags.Inherited)) parts.Add("I (Inherited)");
            return parts.Count > 0 ? string.Join(", ", parts) : $"(raw: {flags})";
        }

        public static string FormatMask(int mask)
        {
            if (mask == 0) return "(none)";
            var names = new List<string>();
            int remaining = mask;
            foreach ((uint bits, var name) in MaskNames)
            {
                if ((remaining & bits) == bits)
                {
                    names.Add(name);
                    remaining &= (int)~bits;
                }
            }
            if (remaining != 0)
                names.Add($"0x{remaining:X8}");  // unnamed bits, raw
            return string.Join(" | ", names) + $" (0x{mask:X8})";
        }
    }
}
