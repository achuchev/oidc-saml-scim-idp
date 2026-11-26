// Built-in .NET Framework fallback of the on-premises SCIM agent, compiled by
// build-windows.bat with the csc.exe that ships with Windows when Go is not
// installed. Keep it to C# 5 language features (no string interpolation, no
// ?. operator, no expression-bodied members) and the assemblies referenced by
// build-windows.bat.
using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace IdentityCloudScimAgent
{
    public class AgentConfig
    {
        public string cloud_idp_url { get; set; }
        public string agent_token { get; set; }
        public string local_scim_base_url { get; set; }
        public string local_scim_bearer_token { get; set; }
        public string local_basic_auth_user { get; set; }
        public string local_basic_auth_password { get; set; }
        public Dictionary<string, string> local_extra_headers { get; set; }
        public string local_ca_cert_file { get; set; }
        public bool local_insecure_skip_tls_verify { get; set; }
        public string cloud_ca_cert_file { get; set; }
        public int poll_wait_seconds { get; set; }
        public int local_timeout_seconds { get; set; }
        public int max_jobs { get; set; }
        public string log_file { get; set; }
        public string service_name { get; set; }
        // Lets -install and an unattended agent go ahead (with warnings) although
        // other accounts can change the agent's files or read config.json.
        public bool allow_insecure_file_permissions { get; set; }
    }

    public class AgentJob
    {
        public string id { get; set; }
        public string method { get; set; }
        public string endpoint_path { get; set; }
        public string body_raw { get; set; }
    }

    public class PollResponse
    {
        public string connector_id { get; set; }
        public string connector_name { get; set; }
        public List<AgentJob> jobs { get; set; }
    }

    // A non-2xx answer from the Identity Cloud relay.
    public class CloudHttpException : Exception
    {
        private readonly int _statusCode;

        public CloudHttpException(int statusCode, string message) : base(message)
        {
            _statusCode = statusCode;
        }

        public int StatusCode { get { return _statusCode; } }
    }

    // An endpoint_path accepted by AgentText.ParseEndpointPath.
    public class ScimEndpoint
    {
        public string[] Segments; // percent-decoded: Resource or Resource/{id}
        public string Query;      // validated query string without '?'

        // Re-encodes the segments like PHP rawurlencode (everything except RFC 3986
        // unreserved characters is percent-encoded), the form the IdP sends.
        public string EscapedPath()
        {
            string[] parts = new string[Segments.Length];
            for (int i = 0; i < Segments.Length; i++) parts[i] = AgentText.EscapeSegment(Segments[i]);
            return string.Join("/", parts);
        }

        public override string ToString()
        {
            return string.IsNullOrEmpty(Query) ? EscapedPath() : EscapedPath() + "?" + Query;
        }
    }

    // Input validation and log-safe text helpers (mirrors the Go agent).
    public static class AgentText
    {
        public const int MaxLogFieldChars = 256;
        public const int MaxCloudErrorChars = 512;
        public const int MaxEndpointPathChars = 8192;
        private const string HexDigits = "0123456789ABCDEF";
        private static readonly string[] AllowedRoots = new string[] { "users", "groups", "serviceproviderconfig", "resourcetypes", "schemas", "bulk", "me", ".search" };
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        public static bool IsUnreserved(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
        }

        private static int HexValue(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        private static bool IsAscii(string s)
        {
            foreach (char c in s)
            {
                if (c >= 0x80) return false;
            }
            return true;
        }

        // Confines an IdP-supplied endpoint_path to the SCIM 2.0 endpoint root:
        // <Resource> or <Resource>/<id> with an allowed resource, optionally with a
        // query string. Segments are percent-decoded before they are checked, so
        // encoded dot segments, encoded slashes or backslashes, ';' path parameters
        // and double encoding are refused.
        public static ScimEndpoint ParseEndpointPath(string ep)
        {
            string trimmed = (ep ?? "").Trim().TrimStart('/');
            if (trimmed.Length == 0) throw new Exception("empty SCIM endpoint_path");
            if (trimmed.Length > MaxEndpointPathChars) throw new Exception("endpoint_path is too long");
            foreach (char c in trimmed)
            {
                if (c <= ' ' || c >= (char)0x7F) throw new Exception("endpoint_path contains a control, space or non-ASCII character");
                if (c == '#' || c == ';' || c == '\\') throw new Exception("endpoint_path contains a forbidden '" + c + "' character");
            }
            string pathOnly = trimmed;
            string query = "";
            int q = trimmed.IndexOf('?');
            if (q >= 0)
            {
                pathOnly = trimmed.Substring(0, q);
                query = trimmed.Substring(q + 1);
            }
            if (!IsValidQuery(query)) throw new Exception("endpoint_path has an invalid query string");
            string[] raw = pathOnly.Split('/');
            if (raw.Length > 2) throw new Exception("endpoint_path must be <Resource> or <Resource>/<id>");
            string[] segs = new string[raw.Length];
            for (int i = 0; i < raw.Length; i++)
            {
                string dec = PercentDecode(raw[i]);
                if (dec.Trim('.', ' ').Length == 0) throw new Exception("empty or dot-segment in endpoint_path");
                if (!IsAllowedSegmentText(dec)) throw new Exception("forbidden character in an endpoint_path segment");
                segs[i] = dec;
            }
            if (!IsAscii(segs[0]) || Array.IndexOf(AllowedRoots, segs[0].ToLowerInvariant()) < 0)
            {
                throw new Exception("disallowed SCIM resource root " + Quote(segs[0], MaxLogFieldChars));
            }
            ScimEndpoint result = new ScimEndpoint();
            result.Segments = segs;
            result.Query = query;
            return result;
        }

        private static string PercentDecode(string raw)
        {
            byte[] buf = new byte[raw.Length];
            int n = 0;
            for (int i = 0; i < raw.Length; i++)
            {
                char c = raw[i];
                if (c == '%')
                {
                    if (i + 2 >= raw.Length || HexValue(raw[i + 1]) < 0 || HexValue(raw[i + 2]) < 0)
                    {
                        throw new Exception("endpoint_path has an invalid percent-encoding");
                    }
                    buf[n++] = (byte)(HexValue(raw[i + 1]) * 16 + HexValue(raw[i + 2]));
                    i += 2;
                }
                else
                {
                    buf[n++] = (byte)c; // ASCII only, checked by the caller
                }
            }
            try
            {
                return StrictUtf8.GetString(buf, 0, n);
            }
            catch (ArgumentException)
            {
                throw new Exception("endpoint_path segment is not valid UTF-8");
            }
        }

        // RFC 3986 query characters with well-formed percent escapes; ';' is refused
        // because some servers treat it as a parameter separator.
        private static bool IsValidQuery(string q)
        {
            for (int i = 0; i < q.Length; i++)
            {
                char c = q[i];
                if (IsUnreserved(c) || "!$&'()*+,=:@/?".IndexOf(c) >= 0) continue;
                if (c == '%' && i + 2 < q.Length && HexValue(q[i + 1]) >= 0 && HexValue(q[i + 2]) >= 0)
                {
                    i += 2;
                    continue;
                }
                return false;
            }
            return true;
        }

        // A decoded segment may not contain separators, '%', '?', '#' or controls;
        // outside ASCII only letters, marks and digits are allowed, so look-alike
        // dots and slashes (such as U+FF0E or U+2215) are refused too.
        private static bool IsAllowedSegmentText(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c < 0x80)
                {
                    if (c < 0x20 || c == 0x7F || c == '/' || c == '\\' || c == ';' || c == '%' || c == '?' || c == '#') return false;
                    continue;
                }
                switch (CharUnicodeInfo.GetUnicodeCategory(s, i))
                {
                    case UnicodeCategory.UppercaseLetter:
                    case UnicodeCategory.LowercaseLetter:
                    case UnicodeCategory.TitlecaseLetter:
                    case UnicodeCategory.ModifierLetter:
                    case UnicodeCategory.OtherLetter:
                    case UnicodeCategory.NonSpacingMark:
                    case UnicodeCategory.SpacingCombiningMark:
                    case UnicodeCategory.EnclosingMark:
                    case UnicodeCategory.DecimalDigitNumber:
                    case UnicodeCategory.LetterNumber:
                    case UnicodeCategory.OtherNumber:
                        break;
                    default:
                        return false;
                }
                if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) i++;
            }
            return true;
        }

        public static string EscapeSegment(string s)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            StringBuilder sb = new StringBuilder(bytes.Length * 3);
            foreach (byte b in bytes)
            {
                if (b < 0x80 && IsUnreserved((char)b))
                {
                    sb.Append((char)b);
                }
                else
                {
                    sb.Append('%').Append(HexDigits[b >> 4]).Append(HexDigits[b & 15]);
                }
            }
            return sb.ToString();
        }

        // The IdP issues canonical 8-4-4-4-12 hex UUIDs as job ids.
        public static bool IsUuid(string s)
        {
            if (s == null || s.Length != 36) return false;
            for (int i = 0; i < 36; i++)
            {
                char c = s[i];
                if (i == 8 || i == 13 || i == 18 || i == 23)
                {
                    if (c != '-') return false;
                }
                else if (HexValue(c) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        // Returns the upper-cased method if the IdP may use it, otherwise null.
        public static string NormalizeMethod(string m)
        {
            string u = (m ?? "").Trim().ToUpperInvariant();
            switch (u)
            {
                case "GET":
                case "POST":
                case "PUT":
                case "PATCH":
                case "DELETE":
                    return u;
            }
            return null;
        }

        public static string Clip(string s, int maxChars)
        {
            if (s == null) return "";
            if (s.Length <= maxChars) return s;
            int cut = maxChars;
            if (cut > 0 && char.IsHighSurrogate(s[cut - 1])) cut--;
            return s.Substring(0, cut) + "...(truncated)";
        }

        private static bool NeedsEscape(string s, int i)
        {
            char c = s[i];
            if (c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F)) return true;
            if (char.IsHighSurrogate(c)) return !(i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]));
            if (char.IsLowSurrogate(c)) return !(i > 0 && char.IsHighSurrogate(s[i - 1]));
            UnicodeCategory cat = CharUnicodeInfo.GetUnicodeCategory(c);
            return cat == UnicodeCategory.Format || cat == UnicodeCategory.LineSeparator || cat == UnicodeCategory.ParagraphSeparator;
        }

        private static void AppendEscape(StringBuilder sb, char c)
        {
            sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
        }

        // Clips s and returns it in double quotes with quotes, backslashes, control,
        // line-separator and format (bidi) characters escaped, so remote text can
        // neither forge nor hide log entries.
        public static string Quote(string s, int maxChars)
        {
            string v = Clip(s, maxChars);
            StringBuilder sb = new StringBuilder(v.Length + 2);
            sb.Append('"');
            for (int i = 0; i < v.Length; i++)
            {
                char c = v[i];
                if (c == '"' || c == '\\')
                {
                    sb.Append('\\').Append(c);
                }
                else if (NeedsEscape(v, i))
                {
                    AppendEscape(sb, c);
                }
                else
                {
                    sb.Append(c);
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        // Escapes control, line-separator and format characters in a whole log line.
        public static string EscapeControls(string s)
        {
            if (s == null) return "";
            StringBuilder sb = null;
            for (int i = 0; i < s.Length; i++)
            {
                if (NeedsEscape(s, i))
                {
                    if (sb == null) sb = new StringBuilder(s, 0, i, s.Length + 16);
                    AppendEscape(sb, s[i]);
                }
                else if (sb != null)
                {
                    sb.Append(s[i]);
                }
            }
            return sb == null ? s : sb.ToString();
        }

        // Service names are used on sc.exe command lines and in the account
        // NT SERVICE\<name>, so only a conservative character set is accepted.
        public static bool IsValidServiceName(string s)
        {
            if (s == null || s.Length < 1 || s.Length > 80) return false;
            foreach (char c in s)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
                if (!ok) return false;
            }
            return true;
        }

        // SID of the NT SERVICE\<name> virtual account: S-1-5-80 followed by the
        // SHA-1 of the upper-cased UTF-16LE service name as five 32-bit values.
        public static string ServiceSid(string serviceName)
        {
            byte[] hash;
            using (SHA1 sha = SHA1.Create())
            {
                hash = sha.ComputeHash(Encoding.Unicode.GetBytes(serviceName.ToUpperInvariant()));
            }
            StringBuilder sb = new StringBuilder("S-1-5-80");
            for (int i = 0; i < 5; i++)
            {
                sb.Append('-').Append(BitConverter.ToUInt32(hash, i * 4).ToString(CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        // Quotes one command-line argument for the MSVCRT/CommandLineToArgvW rules.
        public static string QuoteArg(string arg)
        {
            if (arg == null) arg = "";
            if (arg.Length > 0 && arg.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return arg;
            StringBuilder sb = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char c in arg)
            {
                if (c == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (c == '"')
                {
                    sb.Append('\\', backslashes * 2 + 1);
                }
                else
                {
                    sb.Append('\\', backslashes);
                }
                sb.Append(c);
                backslashes = 0;
            }
            sb.Append('\\', backslashes * 2);
            sb.Append('"');
            return sb.ToString();
        }
    }

    // Checks who can read or change the files the agent depends on (mirrors
    // acl.go in the Go agent). Trusted are SYSTEM, Administrators,
    // TrustedInstaller, the service account, the account running this process,
    // the built-in Administrator account and the Domain and Enterprise Admins
    // groups; the CREATOR OWNER / CREATOR GROUP / OWNER RIGHTS placeholders are
    // ignored because the owner is judged on its own.
    public class PermissionChecker
    {
        public const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        private const uint AccessReadData = 0x1u, AccessWriteData = 0x2u, AccessAppendData = 0x4u, AccessDeleteChild = 0x40u,
            AccessDelete = 0x10000u, AccessWriteDac = 0x40000u, AccessWriteOwner = 0x80000u,
            AccessGenericAll = 0x10000000u, AccessGenericWrite = 0x40000000u, AccessGenericRead = 0x80000000u;
        // Rights that let an account change, replace, delete or re-permission a
        // file, or add, remove or replace the entries of a folder.
        public const uint RightsModify = AccessWriteData | AccessAppendData | AccessDeleteChild | AccessDelete
            | AccessWriteDac | AccessWriteOwner | AccessGenericAll | AccessGenericWrite;
        // Rights that let an account rename, remove or re-permission a folder and
        // so replace everything below it.
        public const uint RightsParent = AccessDeleteChild | AccessDelete | AccessWriteDac | AccessWriteOwner | AccessGenericAll;
        // Rights that let an account read or change a file that holds secrets.
        public const uint RightsSecret = RightsModify | AccessReadData | AccessGenericRead;

        private readonly HashSet<string> _trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _checked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> _problems = new List<string>();

        public PermissionChecker(string serviceName)
        {
            foreach (string sid in new string[] { "S-1-5-18", "S-1-5-32-544", TrustedInstallerSid, "S-1-3-0", "S-1-3-1", "S-1-3-4", AgentText.ServiceSid(serviceName) })
            {
                _trusted.Add(sid);
            }
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    if (id.User != null) _trusted.Add(id.User.Value);
                }
            }
            catch (Exception)
            {
            }
        }

        public bool IsTrusted(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return false;
            if (_trusted.Contains(sid)) return true;
            // S-1-5-21-<machine or domain>-<RID>: the built-in Administrator account
            // (500), Domain Admins (512) and Enterprise Admins (519).
            string[] parts = sid.Split('-');
            if (parts.Length == 8 && parts[3] == "21")
            {
                return parts[7] == "500" || parts[7] == "512" || parts[7] == "519";
            }
            return false;
        }

        private static string Describe(string sid)
        {
            if (string.IsNullOrEmpty(sid)) return "no account";
            try
            {
                return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value + " (" + sid + ")";
            }
            catch (Exception)
            {
                return sid;
            }
        }

        private static string DescribeRights(uint r)
        {
            List<string> parts = new List<string>();
            if ((r & AccessGenericAll) != 0) parts.Add("take full control");
            if ((r & (AccessReadData | AccessGenericRead)) != 0) parts.Add("read");
            if ((r & (AccessWriteData | AccessAppendData | AccessGenericWrite)) != 0) parts.Add("write");
            if ((r & (AccessDelete | AccessDeleteChild)) != 0) parts.Add("delete");
            if ((r & (AccessWriteDac | AccessWriteOwner)) != 0) parts.Add("change permissions or owner");
            return string.Join(", ", parts.ToArray());
        }

        // Checks a file or folder once: records a problem for an owner outside the
        // trusted set and for every such account that holds a right in mask.
        // Inherit-only entries only shape future children and deny entries are
        // ignored, which can only make the check stricter. Permissions that
        // cannot be read count as a problem.
        public void Check(string what, string path, uint mask, bool isFolder)
        {
            if (string.IsNullOrEmpty(path)) return;
            string full;
            try
            {
                full = Path.GetFullPath(path);
            }
            catch (Exception)
            {
                full = path;
            }
            if (!_checked.Add(full.Length > 3 ? full.TrimEnd('\\') : full)) return;
            try
            {
                AccessControlSections sections = AccessControlSections.Access | AccessControlSections.Owner;
                FileSystemSecurity sec = isFolder
                    ? (FileSystemSecurity)Directory.GetAccessControl(full, sections)
                    : (FileSystemSecurity)File.GetAccessControl(full, sections);
                IdentityReference owner = sec.GetOwner(typeof(SecurityIdentifier));
                string ownerSid = owner == null ? null : owner.Value;
                if (!IsTrusted(ownerSid)) _problems.Add(what + " " + full + ": it is owned by " + Describe(ownerSid));
                List<string> order = new List<string>();
                Dictionary<string, uint> rights = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
                foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule.AccessControlType != AccessControlType.Allow) continue;
                    if ((rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                    uint r = unchecked((uint)(int)rule.FileSystemRights) & mask;
                    string sid = rule.IdentityReference.Value;
                    if (r == 0 || IsTrusted(sid)) continue;
                    if (!rights.ContainsKey(sid))
                    {
                        order.Add(sid);
                        rights[sid] = 0;
                    }
                    rights[sid] = rights[sid] | r;
                }
                foreach (string sid in order)
                {
                    _problems.Add(what + " " + full + ": " + Describe(sid) + " may " + DescribeRights(rights[sid]));
                }
            }
            catch (Exception ex)
            {
                _problems.Add(what + " " + full + ": cannot read its permissions: " + ex.Message);
            }
        }

        // Checks every folder above path, up to the volume root, for rights that
        // let an account rename, remove or re-permission it. Folders checked
        // before (with the wider RightsModify) are skipped.
        public void CheckParents(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            string d;
            try
            {
                d = Path.GetDirectoryName(Path.GetFullPath(path));
            }
            catch (Exception)
            {
                return;
            }
            while (!string.IsNullOrEmpty(d))
            {
                string up = Path.GetDirectoryName(d);
                uint mask = RightsParent;
                if (string.IsNullOrEmpty(up)) mask &= ~AccessDelete; // a volume root cannot be renamed or removed
                Check("parent folder", d, mask, true);
                d = up;
            }
        }

        // What a new service depends on: no untrusted account may change
        // scim-agent.exe, the program, config or log folder (including adding
        // files to them), or rename or re-permission a folder above them.
        // config.json itself is not checked because -install resets it.
        public List<string> InstallTargets(string exePath, string configPath, string logDir)
        {
            string exeDir = Path.GetDirectoryName(Path.GetFullPath(exePath));
            string configDir = Path.GetDirectoryName(Path.GetFullPath(configPath));
            Check("program file", exePath, RightsModify, false);
            Check("program folder", exeDir, RightsModify, true);
            Check("config folder", configDir, RightsModify, true);
            Check("log folder", logDir, RightsModify, true);
            CheckParents(exeDir);
            CheckParents(configDir);
            CheckParents(logDir);
            return _problems;
        }

        // No untrusted account may read or change config.json (the agent token
        // and the local SCIM credentials) or own it.
        public List<string> ConfigFile(string configPath)
        {
            Check("config.json", configPath, RightsSecret, false);
            return _problems;
        }
    }

    public class ScimProxyEngine
    {
        public const string AgentVersion = "1.1.0";
        public const int MaxLocalResponseBytes = 512 * 1024;
        public const int MaxPollResponseBytes = 8 * 1024 * 1024;
        public const int MaxCloudReplyBytes = 1024 * 1024;
        public const long MaxLogBytes = 10 * 1024 * 1024;
        public const int LogGenerations = 5;
        public const int DefaultMaxJobs = 5;
        public const int HardMaxJobsPerPoll = 10;

        private readonly AgentConfig _cfg;
        private readonly string _logPath;
        private readonly object _logLock = new object();
        private volatile bool _stopping;
        private readonly JavaScriptSerializer _json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };

        public ScimProxyEngine(AgentConfig cfg, string configDir)
        {
            _cfg = cfg;
            if (!string.IsNullOrWhiteSpace(cfg.log_file))
            {
                _logPath = Program.ResolvePath(configDir, cfg.log_file);
            }
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; // TLS 1.2 (value 3072)
        }

        public int LocalTimeoutSeconds
        {
            get
            {
                int t = _cfg.local_timeout_seconds;
                return (t > 0 && t <= 120) ? t : 20;
            }
        }

        public int MaxJobs
        {
            get
            {
                int m = _cfg.max_jobs;
                if (m <= 0) return DefaultMaxJobs;
                return m > HardMaxJobsPerPoll ? HardMaxJobsPerPoll : m;
            }
        }

        public void Log(string msg)
        {
            string line = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "Z " + AgentText.EscapeControls(msg);
            if (Environment.UserInteractive)
            {
                Console.WriteLine(line);
            }
            if (!string.IsNullOrEmpty(_logPath))
            {
                lock (_logLock)
                {
                    try
                    {
                        FileInfo fi = new FileInfo(_logPath);
                        if (fi.Exists && fi.Length > MaxLogBytes) RotateLog();
                        File.AppendAllText(_logPath, line + Environment.NewLine, Encoding.UTF8);
                    }
                    catch { }
                }
            }
        }

        // Keeps LogGenerations rotated files (log.1 newest ... log.5 oldest), so a
        // burst of output cannot wipe the history in one go.
        private void RotateLog()
        {
            string oldest = _logPath + "." + LogGenerations;
            if (File.Exists(oldest)) File.Delete(oldest);
            for (int i = LogGenerations - 1; i >= 1; i--)
            {
                string src = _logPath + "." + i;
                if (File.Exists(src)) File.Move(src, _logPath + "." + (i + 1));
            }
            File.Move(_logPath, _logPath + ".1");
        }

        // Returns null when the log file can be opened for appending, otherwise the error.
        public string CheckLogWritable()
        {
            if (string.IsNullOrEmpty(_logPath)) return null;
            try
            {
                string dir = Path.GetDirectoryName(_logPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                using (new FileStream(_logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete))
                {
                }
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public void Stop() { _stopping = true; }

        // Reads at most maxBytes of a response body before deadlineUtc. A longer
        // body is cut (on a UTF-8 boundary) and reported through truncated.
        private static byte[] ReadBounded(Stream s, int maxBytes, DateTime deadlineUtc, out bool truncated)
        {
            truncated = false;
            byte[] all;
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buf = new byte[16384];
                while (true)
                {
                    if (DateTime.UtcNow > deadlineUtc) throw new TimeoutException("timed out reading the HTTP response body");
                    long room = (long)maxBytes + 1 - ms.Length;
                    if (room <= 0) break;
                    int n = s.Read(buf, 0, (int)Math.Min((long)buf.Length, room));
                    if (n <= 0) break;
                    ms.Write(buf, 0, n);
                }
                all = ms.ToArray();
            }
            if (all.Length <= maxBytes) return all;
            truncated = true;
            int cut = maxBytes;
            for (int i = 0; i < 3 && cut > 0 && (all[cut] & 0xC0) == 0x80; i++) cut--;
            if ((all[cut] & 0xC0) == 0x80) cut = maxBytes;
            byte[] head = new byte[cut];
            Buffer.BlockCopy(all, 0, head, 0, cut);
            return head;
        }

        // Builds the request URI below local_scim_base_url and re-checks the result
        // (System.Uri may canonicalize the path): same scheme and authority, still
        // under the base path, the same number of segments and no dot segments.
        private Uri BuildLocalUri(ScimEndpoint ep)
        {
            string baseStr = (_cfg.local_scim_base_url ?? "").Trim().TrimEnd('/');
            Uri baseUri = new Uri(baseStr + "/", UriKind.Absolute);
            Uri target = new Uri(baseStr + "/" + ep.ToString(), UriKind.Absolute);
            string basePath = baseUri.AbsolutePath;
            string targetPath = target.AbsolutePath;
            bool ok = string.Equals(target.Scheme, baseUri.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(target.Authority, baseUri.Authority, StringComparison.OrdinalIgnoreCase)
                && targetPath.StartsWith(basePath, StringComparison.Ordinal)
                && targetPath.Length > basePath.Length
                && target.Fragment.Length == 0;
            if (ok)
            {
                string[] rel = targetPath.Substring(basePath.Length).Split('/');
                ok = rel.Length == ep.Segments.Length;
                foreach (string seg in rel)
                {
                    if (Uri.UnescapeDataString(seg).Trim('.', ' ').Length == 0) ok = false;
                }
            }
            if (!ok) throw new Exception("endpoint_path escapes local_scim_base_url");
            return target;
        }

        // Validates one IdP job and runs it against the local SCIM application.
        // label describes the job for the log: the normalized method and endpoint
        // when they are valid, otherwise the quoted, clipped values from the IdP.
        public Dictionary<string, object> ExecuteLocalJob(AgentJob job, out string label)
        {
            var res = new Dictionary<string, object>();
            res["job_id"] = job.id;
            label = AgentText.Quote(job.method, AgentText.MaxLogFieldChars) + " " + AgentText.Quote(job.endpoint_path, AgentText.MaxLogFieldChars);
            try
            {
                ScimEndpoint ep = AgentText.ParseEndpointPath(job.endpoint_path);
                string method = AgentText.NormalizeMethod(job.method);
                if (method == null) throw new Exception("unsupported HTTP method " + AgentText.Quote(job.method, AgentText.MaxLogFieldChars));
                label = method + " " + AgentText.Quote("/" + ep.ToString(), AgentText.MaxLogFieldChars);
                Uri target = BuildLocalUri(ep);

                int timeoutMs = LocalTimeoutSeconds * 1000;
                DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(target);
                req.Method = method;
                req.AllowAutoRedirect = false;
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.Accept = "application/scim+json, application/json";
                req.UserAgent = "IdentityCloud-OnPrem-SCIM-Agent/" + AgentVersion;

                if (_cfg.local_insecure_skip_tls_verify)
                {
                    req.ServerCertificateValidationCallback = (s, cert, chain, errs) => true;
                }

                if (!string.IsNullOrWhiteSpace(_cfg.local_scim_bearer_token))
                {
                    req.Headers["Authorization"] = "Bearer " + _cfg.local_scim_bearer_token.Trim();
                }
                else if (!string.IsNullOrWhiteSpace(_cfg.local_basic_auth_user))
                {
                    string pair = _cfg.local_basic_auth_user + ":" + (_cfg.local_basic_auth_password ?? "");
                    req.Headers["Authorization"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(pair));
                }

                if (_cfg.local_extra_headers != null)
                {
                    foreach (var kv in _cfg.local_extra_headers)
                    {
                        if (!string.IsNullOrWhiteSpace(kv.Key)) req.Headers[kv.Key] = kv.Value;
                    }
                }

                if (!string.IsNullOrEmpty(job.body_raw) && method != "GET" && method != "DELETE")
                {
                    byte[] bodyBytes = Encoding.UTF8.GetBytes(job.body_raw);
                    req.ContentType = "application/scim+json; charset=utf-8";
                    req.ContentLength = bodyBytes.Length;
                    using (Stream rs = req.GetRequestStream())
                    {
                        rs.Write(bodyBytes, 0, bodyBytes.Length);
                    }
                }

                HttpWebResponse httpResp = null;
                try
                {
                    httpResp = (HttpWebResponse)req.GetResponse();
                }
                catch (WebException wex)
                {
                    httpResp = wex.Response as HttpWebResponse;
                    if (httpResp == null) throw;
                }

                using (httpResp)
                using (Stream s = httpResp.GetResponseStream())
                {
                    bool truncated;
                    byte[] body = ReadBounded(s, MaxLocalResponseBytes, deadline, out truncated);
                    res["status"] = (int)httpResp.StatusCode;
                    res["body_raw"] = Encoding.UTF8.GetString(body);
                    if (truncated) res["truncated"] = true;
                }
            }
            catch (Exception ex)
            {
                // Local transport errors can be long (they may quote the request
                // URL); the IdP only needs the gist.
                res["status"] = 0;
                res["error"] = AgentText.Clip(ex.Message, AgentText.MaxCloudErrorChars);
            }
            return res;
        }

        private string PostCloudJson(string subPath, object payloadObj, int timeoutMs, int maxReplyBytes)
        {
            string url = _cfg.cloud_idp_url.Trim().TrimEnd('/') + subPath;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.AllowAutoRedirect = false;
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.ContentType = "application/json";
            req.Accept = "application/json";
            req.UserAgent = "IdentityCloud-OnPrem-SCIM-Agent/" + AgentVersion;
            req.Headers["Authorization"] = "Bearer " + _cfg.agent_token.Trim();
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);

            byte[] bytes = Encoding.UTF8.GetBytes(_json.Serialize(payloadObj));
            req.ContentLength = bytes.Length;
            using (Stream rs = req.GetRequestStream())
            {
                rs.Write(bytes, 0, bytes.Length);
            }

            HttpWebResponse resp;
            try
            {
                resp = (HttpWebResponse)req.GetResponse();
            }
            catch (WebException wex)
            {
                resp = wex.Response as HttpWebResponse;
                if (resp == null) throw;
            }
            using (resp)
            {
                int status = (int)resp.StatusCode;
                bool ok = status >= 200 && status < 300;
                bool truncated;
                byte[] body;
                using (Stream s = resp.GetResponseStream())
                {
                    body = ReadBounded(s, ok ? maxReplyBytes : AgentText.MaxCloudErrorChars, deadline, out truncated);
                }
                string text = Encoding.UTF8.GetString(body);
                if (!ok)
                {
                    throw new CloudHttpException(status, "cloud " + subPath + " returned HTTP " + status + ": " + AgentText.Quote(text.Trim(), AgentText.MaxCloudErrorChars));
                }
                if (truncated) throw new Exception("cloud " + subPath + " response is larger than " + maxReplyBytes + " bytes");
                return text;
            }
        }

        private static Dictionary<string, object> ResultBatch(Dictionary<string, object> r)
        {
            var batch = new Dictionary<string, object>();
            batch["results"] = new List<Dictionary<string, object>> { r };
            return batch;
        }

        // Posts one job result right after the job ran ({"results":[...]} works with
        // every IdP version). If the IdP refuses it as too large (HTTP 413), the job
        // is reported as failed so the IdP stops waiting for it.
        private void PostResult(Dictionary<string, object> r)
        {
            try
            {
                PostCloudJson("/scim/agent/result", ResultBatch(r), 15000, MaxCloudReplyBytes);
            }
            catch (CloudHttpException ex)
            {
                if (ex.StatusCode != 413 || r.ContainsKey("error")) throw;
                var failed = new Dictionary<string, object>();
                failed["job_id"] = r["job_id"];
                failed["status"] = 0;
                failed["error"] = "local SCIM response (HTTP " + Convert.ToString(r["status"], CultureInfo.InvariantCulture) + ") is too large for the IdP to accept";
                PostCloudJson("/scim/agent/result", ResultBatch(failed), 15000, MaxCloudReplyBytes);
            }
        }

        private void SleepUnlessStopping(int ms)
        {
            for (int waited = 0; waited < ms && !_stopping; waited += 250)
            {
                Thread.Sleep(Math.Min(250, ms - waited));
            }
        }

        private static string RedactUserInfo(string url)
        {
            Uri u;
            if (url != null && Uri.TryCreate(url.Trim(), UriKind.Absolute, out u) && !string.IsNullOrEmpty(u.UserInfo))
            {
                return u.Scheme + "://***@" + u.Authority + u.AbsolutePath;
            }
            return url;
        }

        private static bool IsPlainHttpNonLoopback(string url)
        {
            Uri u;
            if (url == null || !Uri.TryCreate(url.Trim(), UriKind.Absolute, out u)) return false;
            return u.Scheme == Uri.UriSchemeHttp && !u.IsLoopback;
        }

        public void RunLoop()
        {
            string host = Environment.MachineName;
            int waitSec = (_cfg.poll_wait_seconds > 0 && _cfg.poll_wait_seconds <= 15) ? _cfg.poll_wait_seconds : 12;
            Log("Starting Identity Cloud On-Premises SCIM 2.0 Proxy Agent v" + AgentVersion + " (.NET fallback) on " + host);
            Log("Cloud IdP : " + _cfg.cloud_idp_url);
            Log("Local SCIM: " + RedactUserInfo(_cfg.local_scim_base_url));
            if (IsPlainHttpNonLoopback(_cfg.cloud_idp_url))
            {
                Log("WARNING: cloud_idp_url uses plain http://, so the agent token and provisioning data cross the network unencrypted. Use https:// outside a local lab.");
            }

            int backoffMs = 1000;
            bool loggedOk = false;

            while (!_stopping)
            {
                DateTime pollStarted = DateTime.UtcNow;
                int executed = 0;
                try
                {
                    var pollReq = new Dictionary<string, object>();
                    pollReq["hostname"] = host;
                    pollReq["version"] = AgentVersion + "-win";
                    pollReq["wait_seconds"] = waitSec;
                    pollReq["max_jobs"] = MaxJobs;
                    pollReq["local_timeout_seconds"] = LocalTimeoutSeconds;
                    string raw = PostCloudJson("/scim/agent/poll", pollReq, (waitSec + 15) * 1000, MaxPollResponseBytes);
                    PollResponse pr = _json.Deserialize<PollResponse>(raw);
                    if (pr != null && pr.jobs != null)
                    {
                        for (int i = 0; i < pr.jobs.Count && !_stopping; i++)
                        {
                            if (i >= HardMaxJobsPerPoll)
                            {
                                Log("Ignoring " + (pr.jobs.Count - i) + " job(s) beyond the per-poll limit of " + HardMaxJobsPerPoll);
                                break;
                            }
                            AgentJob j = pr.jobs[i];
                            if (j == null) continue;
                            if (!AgentText.IsUuid(j.id))
                            {
                                Log("[JOB " + AgentText.Quote(j.id, AgentText.MaxLogFieldChars) + "] rejected: job id is not a UUID (method "
                                    + AgentText.Quote(j.method, AgentText.MaxLogFieldChars) + ", endpoint_path "
                                    + AgentText.Quote(j.endpoint_path, AgentText.MaxLogFieldChars) + ")");
                                continue;
                            }
                            Stopwatch sw = Stopwatch.StartNew();
                            string label;
                            Dictionary<string, object> r = ExecuteLocalJob(j, out label);
                            executed++;
                            if (r.ContainsKey("error"))
                            {
                                Log("[JOB " + j.id + "] " + label + " -> ERROR (" + sw.ElapsedMilliseconds + "ms): "
                                    + AgentText.Quote(Convert.ToString(r["error"], CultureInfo.InvariantCulture), AgentText.MaxCloudErrorChars));
                            }
                            else
                            {
                                Log("[JOB " + j.id + "] " + label + " -> HTTP " + r["status"] + " (" + sw.ElapsedMilliseconds + "ms)"
                                    + (r.ContainsKey("truncated") ? " (response body truncated)" : ""));
                            }
                            PostResult(r);
                        }
                    }

                    // As in the Go agent, only a well-formed poll whose results were
                    // all delivered resets the backoff: a malformed 2xx body must not
                    // force a new poll (and log entry) every second.
                    backoffMs = 1000;
                    if (!loggedOk)
                    {
                        Log("Connected to Identity Cloud relay - awaiting SCIM provisioning jobs.");
                        loggedOk = true;
                    }
                }
                catch (Exception ex)
                {
                    if (_stopping) break;
                    loggedOk = false;
                    // The message can carry the whole poll response (a
                    // JavaScriptSerializer error includes its entire input), so it
                    // is clipped like a cloud error body; Log escapes control
                    // characters.
                    Log("Relay poll error: " + AgentText.Clip(ex.Message, AgentText.MaxCloudErrorChars) + " (retrying in " + (backoffMs / 1000) + "s)");
                    SleepUnlessStopping(backoffMs);
                    backoffMs = Math.Min(30000, backoffMs * 2);
                    continue;
                }
                if (executed == 0)
                {
                    // The IdP holds an empty poll open for wait_seconds; do not spin
                    // when a poll returns early without a job that could run.
                    int elapsed = (int)(DateTime.UtcNow - pollStarted).TotalMilliseconds;
                    if (elapsed < 1000) SleepUnlessStopping(1000 - elapsed);
                }
            }
            Log("SCIM Proxy Agent stopped cleanly.");
        }
    }

    public class ScimWindowsService : ServiceBase
    {
        private readonly ScimProxyEngine _engine;
        private Thread _worker;

        public ScimWindowsService(ScimProxyEngine engine, string svcName)
        {
            ServiceName = svcName;
            CanStop = true;
            CanShutdown = true;
            _engine = engine;
        }

        protected override void OnStart(string[] args)
        {
            _worker = new Thread(_engine.RunLoop) { IsBackground = true };
            _worker.Start();
        }

        protected override void OnStop()
        {
            _engine.Stop();
            if (_worker != null) _worker.Join(8000);
        }

        protected override void OnShutdown() { OnStop(); }
    }

    public static class Program
    {
        private const string DefaultServiceName = "IdentityCloudScimAgent";
        private const string DisplayName = "Identity Cloud On-Premises SCIM 2.0 Proxy Agent";
        private const string Description = "Outbound-only HTTPS relay agent that receives SCIM 2.0 provisioning operations from Identity Cloud and applies them to an internal on-premises SCIM application.";

        public static int Main(string[] args)
        {
            string exePath = Assembly.GetExecutingAssembly().Location;
            string exeDir = Path.GetDirectoryName(exePath);
            string configPath = Path.Combine(exeDir, "config.json");
            bool consoleMode = false, doInstall = false, doUninstall = false, doStart = false, doStop = false, doTestLocal = false;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if ((a == "-config" || a == "--config") && i + 1 < args.Length) configPath = Path.GetFullPath(args[++i]);
                else if (a == "-console" || a == "--console") consoleMode = true;
                else if (a == "-install" || a == "--install") doInstall = true;
                else if (a == "-uninstall" || a == "--uninstall") doUninstall = true;
                else if (a == "-start" || a == "--start") doStart = true;
                else if (a == "-stop" || a == "--stop") doStop = true;
                else if (a == "-test-local" || a == "--test-local") doTestLocal = true;
            }

            if (!File.Exists(configPath) && !doUninstall && !doStop)
            {
                Console.Error.WriteLine("Missing configuration file: " + configPath);
                return 1;
            }

            AgentConfig cfg = null;
            if (File.Exists(configPath))
            {
                try
                {
                    cfg = new JavaScriptSerializer().Deserialize<AgentConfig>(File.ReadAllText(configPath, Encoding.UTF8));
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Invalid JSON in " + configPath + ": " + ex.Message);
                    return 1;
                }
            }
            if (cfg == null) cfg = new AgentConfig();
            string configDir = Path.GetDirectoryName(configPath);
            string svcName = string.IsNullOrWhiteSpace(cfg.service_name) ? DefaultServiceName : cfg.service_name.Trim();

            if ((doInstall || doUninstall || doStart || doStop) && !AgentText.IsValidServiceName(svcName))
            {
                Console.Error.WriteLine("service_name " + AgentText.Quote(svcName, 100) + " is invalid: use 1-80 characters from A-Z, a-z, 0-9, '_', '.' and '-'");
                return 1;
            }

            if (doInstall)
            {
                string installError = ValidateConfig(cfg);
                if (installError != null)
                {
                    Console.Error.WriteLine("Error validating " + configPath + " before service install: " + installError);
                    return 1;
                }
                string logPath = string.IsNullOrWhiteSpace(cfg.log_file) ? null : ResolvePath(configDir, cfg.log_file);
                return InstallService(svcName, exePath, configPath, logPath, cfg.allow_insecure_file_permissions);
            }
            if (doUninstall) { RunSc("stop", svcName); return RunSc("delete", svcName); }
            if (doStart) return RunSc("start", svcName);
            if (doStop) return RunSc("stop", svcName);

            string cfgError = ValidateConfig(cfg);
            if (cfgError != null)
            {
                Console.Error.WriteLine("Configuration error: " + cfgError);
                return 1;
            }

            var engine = new ScimProxyEngine(cfg, configDir);
            bool interactive = consoleMode || Environment.UserInteractive;
            if (!doTestLocal && !interactive)
            {
                // A service has no console: refuse to run without its log file. The
                // Service Control Manager then reports the failed start.
                if (engine.CheckLogWritable() != null) return 1;
                if (RunningAsLocalSystem())
                {
                    engine.Log("WARNING: the service runs as LocalSystem. Run scim-agent.exe -uninstall and then -install to switch it to the least-privileged NT SERVICE\\" + svcName + " account.");
                }
            }
            // Unattended means a service or a process started by a service wrapper.
            if (!CheckConfigPermissions(engine, cfg, configPath, svcName, !doTestLocal && !Environment.UserInteractive)) return 1;

            if (doTestLocal)
            {
                string label;
                var r = engine.ExecuteLocalJob(new AgentJob { id = "local-self-test", method = "GET", endpoint_path = "Users?startIndex=1&count=1" }, out label);
                if (r.ContainsKey("error")) { Console.Error.WriteLine("LOCAL SCIM TEST FAILED: " + r["error"]); return 1; }
                Console.WriteLine("LOCAL SCIM TEST HTTP " + r["status"] + ":\n" + r["body_raw"]);
                return ((int)r["status"] >= 200 && (int)r["status"] < 300) ? 0 : 1;
            }

            if (interactive)
            {
                Console.CancelKeyPress += (s, e) => { e.Cancel = true; engine.Stop(); };
                engine.RunLoop();
                return 0;
            }

            ServiceBase.Run(new ScimWindowsService(engine, svcName));
            return 0;
        }

        internal static string ResolvePath(string dir, string p)
        {
            p = (p ?? "").Trim();
            if (p.Length == 0) return p;
            return Path.IsPathRooted(p) ? p : Path.Combine(dir, p);
        }

        private static string ValidateConfig(AgentConfig cfg)
        {
            string cloud = (cfg.cloud_idp_url ?? "").Trim();
            if (cloud.Length == 0) return "cloud_idp_url is required in config.json";
            if (!cloud.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !cloud.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                return "cloud_idp_url must start with https:// (or http:// for local lab)";
            }
            if (!(cfg.agent_token ?? "").Trim().StartsWith("idp_sagt_", StringComparison.Ordinal))
            {
                return "agent_token must be a valid Identity Cloud SCIM Agent token starting with idp_sagt_";
            }
            string local = (cfg.local_scim_base_url ?? "").Trim().TrimEnd('/');
            if (local.Length == 0) return "local_scim_base_url is required in config.json";
            Uri lu;
            if (!Uri.TryCreate(local, UriKind.Absolute, out lu) || (lu.Scheme != Uri.UriSchemeHttp && lu.Scheme != Uri.UriSchemeHttps) || string.IsNullOrEmpty(lu.Host))
            {
                return "local_scim_base_url must be an absolute http:// or https:// URL";
            }
            if (local.IndexOf('?') >= 0 || local.IndexOf('#') >= 0)
            {
                return "local_scim_base_url must not contain a query string or fragment";
            }
            if (!string.IsNullOrWhiteSpace(cfg.local_ca_cert_file) || !string.IsNullOrWhiteSpace(cfg.cloud_ca_cert_file))
            {
                return "local_ca_cert_file and cloud_ca_cert_file are not supported by the built-in .NET fallback agent. "
                    + "Import the CA certificate into the Local Machine 'Trusted Root Certification Authorities' store "
                    + "(certlm.msc, or: certutil -addstore Root ca.pem) and remove these keys, or build the Go agent, which supports them.";
            }
            return null;
        }

        // config.json holds the agent token and the local SCIM credentials, and its
        // permissions can be wrong although -install restricted them once (1.0.x
        // installs upgraded by replacing the executable, -console runs, service
        // wrappers, an editor that re-created the file). Logs every way in which
        // accounts other than SYSTEM, Administrators, TrustedInstaller, the
        // service account and the account running the agent can read or change
        // it. Returns false when the agent must not start: it runs unattended and
        // allow_insecure_file_permissions is not set.
        private static bool CheckConfigPermissions(ScimProxyEngine engine, AgentConfig cfg, string configPath, string svcName, bool unattended)
        {
            List<string> problems = new PermissionChecker(svcName).ConfigFile(configPath);
            if (problems.Count == 0) return true;
            foreach (string p in problems) engine.Log("WARNING: insecure file permissions: " + p);
            if (!unattended || cfg.allow_insecure_file_permissions) return true;
            string refusal = "Refusing to start because of the permission problems above: " + configPath + " holds the agent token, so only SYSTEM, Administrators and NT SERVICE\\" + svcName
                + " may read or change it. Restrict it by running scim-agent.exe -uninstall and -install from an elevated prompt (or with the icacls commands in README.md), "
                + "or set \"allow_insecure_file_permissions\": true in config.json to start anyway.";
            engine.Log(refusal);
            // Log() prints only to an interactive console; service wrappers capture stderr.
            foreach (string p in problems) Console.Error.WriteLine("WARNING: insecure file permissions: " + AgentText.EscapeControls(p));
            Console.Error.WriteLine(refusal);
            return false;
        }

        private static bool IsElevated()
        {
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool RunningAsLocalSystem()
        {
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    return id.User != null && id.User.Value == "S-1-5-18";
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string NormDir(string p)
        {
            return Path.GetFullPath(p).TrimEnd('\\').ToLowerInvariant();
        }

        private static bool PathEquals(string a, string b)
        {
            return NormDir(a) == NormDir(b);
        }

        private static bool PathWithin(string p, string root)
        {
            if (string.IsNullOrEmpty(root)) return false;
            string np = NormDir(p);
            string nr = NormDir(root);
            return np == nr || np.StartsWith(nr + "\\", StringComparison.Ordinal);
        }

        private static string[] SharedRoots()
        {
            return new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetEnvironmentVariable("ProgramW6432"),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            };
        }

        private static List<string> ProfileRoots()
        {
            List<string> roots = new List<string>();
            string drive = Environment.GetEnvironmentVariable("SystemDrive");
            if (!string.IsNullOrEmpty(drive)) roots.Add(drive + "\\Users");
            foreach (string v in new string[] { Environment.GetEnvironmentVariable("PUBLIC"), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) })
            {
                if (string.IsNullOrEmpty(v)) continue;
                string parent = Path.GetDirectoryName(v.TrimEnd('\\'));
                if (!string.IsNullOrEmpty(parent)) roots.Add(parent);
            }
            return roots;
        }

        // Why the service must not get an inheritable Modify grant on dir (drive
        // and share roots, the Windows folder, the shared Program Files/ProgramData
        // folders themselves, user profiles), or null when dir is acceptable.
        private static string UnsafeLogDirReason(string dir)
        {
            string d = Path.GetFullPath(dir).TrimEnd('\\');
            string root = (Path.GetPathRoot(d) ?? "").TrimEnd('\\');
            if (d.Length == 0 || string.Equals(d, root, StringComparison.OrdinalIgnoreCase)) return "it is a drive or share root";
            if (PathWithin(d, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return "it is inside the Windows folder";
            foreach (string s in SharedRoots())
            {
                if (!string.IsNullOrEmpty(s) && PathEquals(d, s)) return "it is the shared folder " + s + " itself";
            }
            foreach (string p in ProfileRoots())
            {
                if (PathWithin(d, p)) return "it is inside the user profiles folder";
            }
            return null;
        }

        private static void Require(int exitCode, string step)
        {
            if (exitCode != 0) throw new Exception(step + " failed with exit code " + exitCode);
        }

        // Installs the service as the virtual account NT SERVICE\<name> (not
        // LocalSystem) with only SeChangeNotifyPrivilege, restricts config.json to
        // SYSTEM and Administrators (full control) plus the service (read), and
        // grants the service Modify on the log folder. It refuses to install while
        // accounts other than SYSTEM, Administrators, TrustedInstaller, the service
        // and the installing administrator can change scim-agent.exe, the program,
        // config or log folder, or the folders above them, unless allowInsecure
        // (allow_insecure_file_permissions) is set; then it only warns. Any
        // failure removes the service again.
        private static int InstallService(string svcName, string exePath, string configPath, string logPath, bool allowInsecure)
        {
            string icacls = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "icacls.exe");
            string sid = AgentText.ServiceSid(svcName);
            string logDir = string.IsNullOrEmpty(logPath) ? null : Path.GetDirectoryName(Path.GetFullPath(logPath));
            if (logDir != null)
            {
                string why = UnsafeLogDirReason(logDir);
                if (why != null)
                {
                    Console.Error.WriteLine("Service install failed: will not grant the service write access to the log folder " + logDir + " because " + why
                        + "; set log_file to a dedicated folder such as C:\\ProgramData\\IdentityCloudScimAgent\\logs\\scim-agent.log");
                    return 1;
                }
            }
            // Fail before creating anything when not elevated, so that the log
            // folder is never created (and owned) by a non-elevated user.
            if (!IsElevated())
            {
                Console.Error.WriteLine("Service install failed: run Command Prompt / PowerShell as Administrator.");
                return 1;
            }
            if (logDir != null)
            {
                try
                {
                    Directory.CreateDirectory(logDir);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Service install failed: cannot create the log folder " + logDir + ": " + ex.Message);
                    return 1;
                }
            }

            List<string> problems = new PermissionChecker(svcName).InstallTargets(exePath, configPath, logDir);
            // Programs running as the user can change folders in a user profile.
            foreach (string[] f in new string[][] { new string[] { "program folder", Path.GetDirectoryName(exePath) }, new string[] { "config folder", Path.GetDirectoryName(configPath) } })
            {
                foreach (string profiles in ProfileRoots())
                {
                    if (PathWithin(f[1], profiles))
                    {
                        problems.Add(f[0] + " " + f[1] + ": it is inside the user profiles folder");
                        break;
                    }
                }
            }
            if (problems.Count > 0)
            {
                string list = "\n  - " + string.Join("\n  - ", problems.ToArray());
                if (!allowInsecure)
                {
                    Console.Error.WriteLine("Service install failed: refusing to install: accounts other than SYSTEM, Administrators, TrustedInstaller, NT SERVICE\\" + svcName
                        + " and you could change files the service runs or trusts:" + list
                        + "\nRestrict these files and folders (see \"Where to put the files\" in README.md), or set \"allow_insecure_file_permissions\": true in config.json to install anyway.");
                    return 1;
                }
                Console.Error.WriteLine("WARNING: installing although other accounts could change files the service runs or trusts, because allow_insecure_file_permissions is set:" + list);
            }

            string bin = AgentText.QuoteArg(exePath) + " -config " + AgentText.QuoteArg(configPath);
            int rc = RunSc("create", svcName, "binPath=", bin, "start=", "auto", "obj=", "NT SERVICE\\" + svcName, "DisplayName=", DisplayName);
            if (rc != 0)
            {
                Console.Error.WriteLine("Service install failed: sc create exited with code " + rc);
                return rc;
            }
            try
            {
                RunSc("description", svcName, Description);
                Require(RunSc("sidtype", svcName, "unrestricted"), "sc sidtype");
                Require(RunSc("privs", svcName, "SeChangeNotifyPrivilege"), "sc privs");
                if (logDir != null)
                {
                    Require(RunTool(icacls, logDir, "/grant:r", "*" + sid + ":(OI)(CI)M"), "icacls on the log folder");
                }
                Require(RunTool(icacls, configPath, "/reset"), "icacls /reset on config.json");
                Require(RunTool(icacls, configPath, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*" + sid + ":R"), "icacls on config.json");
                Require(RunTool(icacls, configPath, "/setowner", "*S-1-5-32-544"), "icacls /setowner on config.json");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Service install failed: " + ex.Message + "; removing the service again.");
                RunSc("delete", svcName);
                return 1;
            }
            Console.WriteLine("Installed Windows Service \"" + svcName + "\" running as NT SERVICE\\" + svcName + " using config " + configPath);
            Console.WriteLine("Run scim-agent.exe -start or sc start " + svcName + " to start.");
            return 0;
        }

        private static int RunTool(string exe, params string[] args)
        {
            StringBuilder cmd = new StringBuilder();
            foreach (string a in args)
            {
                if (cmd.Length > 0) cmd.Append(' ');
                cmd.Append(AgentText.QuoteArg(a));
            }
            ProcessStartInfo psi = new ProcessStartInfo(exe, cmd.ToString());
            psi.UseShellExecute = false;
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit();
                return p.ExitCode;
            }
        }

        private static int RunSc(params string[] args)
        {
            return RunTool(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"), args);
        }
    }
}
