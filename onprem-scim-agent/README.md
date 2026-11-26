# Identity Cloud — On-Premises Windows SCIM 2.0 Proxy Agent

Standalone, zero-dependency Go agent (`scim-agent.exe`) for Windows that bridges **Identity Cloud** (your IdP, for example `idp.example.com`) to internal on-premises applications over **SCIM 2.0** without opening any inbound firewall ports.

## How It Works

1. **Outbound-Only HTTPS (Port 443):** `scim-agent.exe` runs inside your Windows network and long-polls `POST {cloud_idp_url}/scim/agent/poll` authenticated with a connector-scoped `idp_sagt_...` Bearer token.
2. **Local SCIM 2.0 Execution:** Whenever Identity Cloud runs **Test**, **Sync Now**, or **Auto-Sync** (creating/updating users, syncing groups, deprovisioning, or optionally pushing passwords), the agent receives the SCIM request, executes it locally against `local_scim_base_url` on your LAN/localhost, and posts the HTTP status & response body back to Identity Cloud as soon as that request has finished.
3. **On-Premises Secrets Stay On-Premises:** Your internal application's URL (`local_scim_base_url`) and credentials (`local_scim_bearer_token` or `local_basic_auth_user` / `local_basic_auth_password`) live only in `config.json` on your Windows server.
4. **Zero Runtime Dependencies:** Uses 100% Go standard library (`go.mod` has zero external modules) and Win32 `advapi32.dll` syscalls to run either interactively or as a native **Windows Service** (`IdentityCloudScimAgent`).

---

## 1. Build `scim-agent.exe`

Zero external dependencies are required on Windows:

- **Option A — Build directly on ANY Windows machine (even WITHOUT Go installed!):**
  Run `build-windows.bat`. If Go is installed it builds the pure-stdlib Go binary (`main.go` + `service_windows.go`); if Go is not installed on that Windows machine, it automatically falls back to Windows' built-in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe` compiler (`win-builtin-fallback\ScimAgent.cs`) to produce `scim-agent.exe` with zero installs!
  ```cmd
  build-windows.bat
  ```
  The .NET fallback applies the same safeguards as the Go agent (endpoint confinement, HTTP method allowlist, bounded reads, quoted logs, least-privilege service install). It does **not** support `local_ca_cert_file` / `cloud_ca_cert_file` and refuses to start when they are set: import your internal CA into the Local Machine **Trusted Root Certification Authorities** store instead (`certlm.msc`, or `certutil -addstore Root ca.pem`), or build the Go agent.

- **Option B — Cross-compile from macOS / Linux with Go 1.21+:**
  ```bash
  ./build-cross-windows.sh
  ```
  Then copy only `scim-agent.exe` and `config.json` to your Windows Server.

---

## 2. Create Connector & Download `config.json`

1. Open the **Identity Cloud Console** → select your **Identity Provider** → **SCIM 2.0 Provisioning** tab.
2. Click **Add Push Connector** and set **Delivery Mode** to **Via On-Prem Windows SCIM Agent**.
3. Configure your sync options (e.g. **Push Groups**, **Auto-Sync**, and optional **Push User Passwords**) and click **Create Connector**.
4. Click **Download `config.json`** and fill in `local_scim_base_url` and `local_scim_bearer_token`.

```json
{
  "cloud_idp_url": "https://idp.example.com/admin-corp",
  "agent_token": "idp_sagt_...",
  "local_scim_base_url": "http://127.0.0.1:8080/scim/v2",
  "local_scim_bearer_token": "YOUR_LOCAL_APP_SCIM_BEARER_TOKEN",
  "local_insecure_skip_tls_verify": false,
  "poll_wait_seconds": 12,
  "local_timeout_seconds": 20,
  "log_file": "logs/scim-agent.log"
}
```

### Where to put the files

`config.json` holds the agent token and your local SCIM credentials, so keep it where only Administrators and the agent can read it. Recommended layout:

| File | Location |
| --- | --- |
| `scim-agent.exe` | `C:\Program Files\IdentityCloudScimAgent\scim-agent.exe` |
| `config.json` | `C:\ProgramData\IdentityCloudScimAgent\config.json` |
| log | `C:\ProgramData\IdentityCloudScimAgent\logs\scim-agent.log` (`"log_file": "logs/scim-agent.log"`) |

Relative paths in `config.json` (`log_file`, `local_ca_cert_file`, `cloud_ca_cert_file`) are resolved against the folder that contains `config.json`. If `config.json` sits next to `scim-agent.exe` (the default when `-config` is omitted), that is the program folder, as before. Keep the log in its own folder (such as `logs/scim-agent.log`): `-install` grants the service write access to the log's folder.

Create the ProgramData folder from an **elevated** prompt, so that a standard user cannot create (and own) it first:

```powershell
mkdir C:\ProgramData\IdentityCloudScimAgent
icacls C:\ProgramData\IdentityCloudScimAgent /setowner *S-1-5-32-544
icacls C:\ProgramData\IdentityCloudScimAgent /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F
```

Do not skip the `icacls` lines: a new folder under `C:\ProgramData` inherits permissions that let every user add files to it, and `-install` refuses such a config folder.

Never install the agent into a folder that standard users can write to, such as a new folder directly under `C:\`, a new folder on another drive or a user profile: anyone who can replace `scim-agent.exe` or `config.json` gets the agent's credentials, and `-install` refuses these locations (see below).

### Optional `config.json` Fields
- `"local_basic_auth_user"` / `"local_basic_auth_password"`: Use HTTP Basic Auth instead of Bearer token when talking to your internal SCIM application.
- `"local_ca_cert_file"`: Path to a custom internal corporate Root CA `.pem` file for HTTPS verification of your internal app (Go agent only).
- `"cloud_ca_cert_file"`: Path to an additional CA `.pem` file for the connection to Identity Cloud (Go agent only).
- `"local_insecure_skip_tls_verify"`: Set `true` only if your internal app uses a self-signed certificate without a CA file.
- `"local_extra_headers"`: Object of extra HTTP headers (`{"X-Tenant": "corp"}`) to include on local SCIM requests.
- `"max_jobs"`: How many jobs the agent asks for per poll (1-10, default 5).
- `"service_name"`: Windows service name (default `IdentityCloudScimAgent`); 1-80 characters from `A-Z a-z 0-9 _ . -`.
- `"allow_insecure_file_permissions"`: Default `false`. Set `true` only as a temporary measure: `-install` then installs, and the service starts, even though other accounts can change the agent's files or read `config.json` (see [File permission checks](#file-permission-checks)). Every problem is still printed or logged as a warning.

---

## 3. Test & Run on Windows

The examples use the recommended layout; omit `-config` if `config.json` is next to `scim-agent.exe`.

### Step A: Verify local SCIM connectivity from Windows
```powershell
cd "C:\Program Files\IdentityCloudScimAgent"
.\scim-agent.exe -test-local -config C:\ProgramData\IdentityCloudScimAgent\config.json
```

### Step B: Run interactively in Console (foreground test)
```powershell
.\scim-agent.exe -console -config C:\ProgramData\IdentityCloudScimAgent\config.json
```
Within seconds, the connector card in the Identity Cloud Console will turn green: **`Agent Online (<Windows-Hostname>)`**. Click **Test** or **Sync Now** in the Cloud Console to verify end-to-end provisioning!

### Step C: Install & Start as an Automatic Windows Service (Run PowerShell/CMD as Administrator)
```powershell
.\scim-agent.exe -install -config C:\ProgramData\IdentityCloudScimAgent\config.json
.\scim-agent.exe -start -config C:\ProgramData\IdentityCloudScimAgent\config.json
```

`-install` sets up a least-privileged service:

- Before it registers the service, it checks the file permissions and refuses to install if other accounts could change what the service runs or trusts (see [File permission checks](#file-permission-checks)).
- The service runs as the virtual account `NT SERVICE\IdentityCloudScimAgent` (`NT SERVICE\<service_name>`), not LocalSystem, and keeps only `SeChangeNotifyPrivilege`.
- `config.json` is reset to SYSTEM and Administrators (full control) plus the service account (read), owned by Administrators. Other local users can no longer read it.
- The service account gets Modify on the log folder. `-install` refuses drive roots, the Windows folder, the shared Program Files / ProgramData folders themselves and user profiles as log folders.
- The service account gets read access to `local_ca_cert_file` / `cloud_ca_cert_file` (Go agent), so they can live in the restricted ProgramData folder.
- If any step fails, the service is removed again.

The equivalent manual commands (for checking an installation, or after moving files) are:

```powershell
icacls C:\ProgramData\IdentityCloudScimAgent\config.json /reset
icacls C:\ProgramData\IdentityCloudScimAgent\config.json /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F "NT SERVICE\IdentityCloudScimAgent:R"
icacls C:\ProgramData\IdentityCloudScimAgent\logs /grant:r "NT SERVICE\IdentityCloudScimAgent:(OI)(CI)M"
icacls C:\ProgramData\IdentityCloudScimAgent\config.json
```

Virtual service accounts need the **Log on as a service** right, which Windows grants to `NT SERVICE\ALL SERVICES` by default. If the service fails to start with error 1069, check that a Group Policy has not removed it.

### File permission checks

Trusted accounts are SYSTEM, Administrators, TrustedInstaller, the service account `NT SERVICE\<service_name>`, the built-in Administrator account, Domain Admins and Enterprise Admins, plus the account that runs `-install` (or, at start, the account the agent runs as). Both agents check:

- **At `-install`:** no other account may own, write to, delete or change the permissions of `scim-agent.exe`, the CA files, the program folder, the folder of `config.json` or the log folder (writing to a folder includes adding files to it), and none may delete, rename or change the permissions of a folder above them. Program and config folders inside a user profile are refused too. The error lists every problem. Fix the permissions (for a dedicated folder, the `icacls` commands under [Where to put the files](#where-to-put-the-files)) and run `-install` again.
- **At every start:** no other account may own, read or change `config.json`. `-test-local` and interactive `-console` runs only print warnings. A service, or any agent started in the non-interactive services session (for example by a service wrapper), logs the problems and refuses to start. This covers installs that were upgraded by replacing the executable, agents that are not run as a service installed by `-install`, and `config.json` files that an editor re-created with the folder's default permissions.

`"allow_insecure_file_permissions": true` in `config.json` turns both refusals into warnings. Use it only temporarily while you fix the permissions.

Check the permissions with `icacls <path>`.

To stop or remove the Windows Service later:
```powershell
.\scim-agent.exe -stop -config C:\ProgramData\IdentityCloudScimAgent\config.json
.\scim-agent.exe -uninstall -config C:\ProgramData\IdentityCloudScimAgent\config.json
```

### Upgrading from agent 1.0.x

Agents before 1.1.0 installed the service as LocalSystem and never restricted `config.json`. If you only replace the executable, the service keeps running as LocalSystem (the agent logs a warning) and, while other users can read `config.json`, it **refuses to start** and logs why (see [File permission checks](#file-permission-checks)). To switch to the hardened setup, run `-stop` and `-uninstall`, move the files to the recommended locations if needed, then run `-install` and `-start` again. To keep the old service running for a short transition, set `"allow_insecure_file_permissions": true` in `config.json`.

Other changes in 1.1.0:

- Relative `log_file` and CA file paths are resolved against the folder of `config.json` (previously the folder of `scim-agent.exe`). Nothing changes when both are in the same folder.
- A service whose `log_file` cannot be opened now refuses to start instead of running without a log. Run the agent with `-console` to see the error.
- `-install` refuses folders that other accounts can change, and an unattended agent refuses to start while other accounts can read `config.json`, unless `allow_insecure_file_permissions` is set.
- `local_scim_base_url` must be an absolute `http://` or `https://` URL without query string or fragment.

---

## Security Notes

- **Endpoint confinement:** the agent only sends `GET`, `POST`, `PUT`, `PATCH` and `DELETE` requests to `<local_scim_base_url>/<Resource>` or `<local_scim_base_url>/<Resource>/<id>`, where `<Resource>` is one of `Users`, `Groups`, `Schemas`, `ResourceTypes`, `ServiceProviderConfig`, `Bulk`, `Me` or `.search`. Path segments are percent-decoded before they are checked, so encoded dot segments (`%2e%2e`), encoded slashes or backslashes, `;` path parameters and double encoding are rejected, and the request URL is re-encoded and re-checked against the base path before it is sent.
- **Job and log integrity:** job ids must be UUIDs. Values received from Identity Cloud are logged quoted and clipped (256 characters per field, 512 for error text), control characters are escaped, and the log keeps five rotated generations of 10 MB (`scim-agent.log.1` … `.5`).
- **Size limits:** poll responses are limited to 8 MiB, response headers to 64 KiB (Go agent; .NET's default is also 64 KB) and relayed local response bodies to 512 KiB (`"truncated": true` is added to a result whose body was cut). Error texts relayed to Identity Cloud or logged are clipped to 512 characters. Each result is posted as soon as its job finishes.
- **File permissions:** see [File permission checks](#file-permission-checks).
- **Transport:** use an `https://` `cloud_idp_url`. With plain `http://` (local lab only) the agent token and provisioning data are not encrypted, and the agent logs a warning.
