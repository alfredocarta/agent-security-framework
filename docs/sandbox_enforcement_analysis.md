# ASF Hermes sandbox enforcement analysis

Scope: read-only inspection of agent-security-framework plus the live Hermes tool path installed under `/Users/alfredo/.hermes/hermes-agent`. No enforcement code or behavior was changed.

Bottom line

ASF currently provides a useful policy hook, audit path, and an opt-in per-tool subprocess sandbox for `terminal` and `execute_code`. It does not currently confine the Hermes agent as a whole at the OS/kernel boundary. A DENY/HITL verdict prevents execution only because the Hermes runtime calls the plugin hook and honors a returned `{"action": "block"}` directive. The macOS Seatbelt profile, when enabled, confines only subprocesses launched by ASF's replacement implementation of `terminal` and `execute_code`. In-process tools such as `read_file`, `write_file`, `patch`, and `search_files` remain in the unconfined Hermes Python process.

Important correction to the requested premise: in the current `wrapper/hermes_mvp.py`, the wrapper's CLI flag is `--no-sandbox`, but the default wrapper path is sandbox enabled because `sandbox=not args.no_sandbox` is passed to `build_env` at lines 133-140. However, outside this wrapper, `asf_core.sandbox_enabled()` defaults `ASF_HERMES_SANDBOX` to false at lines 431-432. So direct Hermes/plugin use is no-sandbox by default, while this wrapper enables sandboxing unless `--no-sandbox` is supplied.

## 1. Live execution path and where ASF sits

The live Hermes path is:

1. `agent/tool_executor.py` parses tool calls and asks plugins for a block message before execution.
   - Concurrent path: `get_pre_tool_call_block_message(...)` at lines 127-136. If non-null, it stores a synthetic blocked result at lines 180-183 and does not schedule the worker.
   - Sequential path: `get_pre_tool_call_block_message(...)` at lines 499-507. If non-null, `_execution_blocked` is true at lines 515-520 and the tool result is synthesized at lines 589-592.
2. Unblocked calls reach `handle_function_call` through `_ra().handle_function_call(..., skip_pre_tool_call_hook=True)` in `agent/tool_executor.py` lines 748-754 and 768-774.
3. `model_tools.handle_function_call` routes to `tools.registry.dispatch` at lines 832-846. If it is called directly without `skip_pre_tool_call_hook=True`, it also invokes `get_pre_tool_call_block_message` at lines 784-799.
4. `tools.registry.dispatch` looks up the handler and executes it in-process at lines 390-405.
5. ASF's plugin wraps `tools.registry.dispatch` in `integrations/hermes/asf_tracker_plugin.py` lines 440-489. That wrapper only substitutes execution for `terminal` and `execute_code` when `_sandbox_enabled()` is true at lines 461-469. All other tools call the original dispatch at line 470.

Therefore ASF has two different roles:

- Pre-tool veto: `on_pre_tool_call` returns a cooperative block directive in enforce mode at lines 542-551, using `asf_core.block_directive` from `wrapper/asf_core.py` lines 145-148.
- Subprocess confinement: the dispatch wrapper intercepts the real dispatch only for `terminal` and `execute_code` when `ASF_HERMES_SANDBOX=true`, replacing the original tool implementation with `_sandbox_terminal` or `_sandbox_execute_code` at `asf_tracker_plugin.py` lines 465-468.

## 2. Enforcement inventory by tool

Legend:

- Cooperative/harness: blocks because Hermes asks the plugin and honors the returned block result.
- OS/kernel: actual syscalls are constrained by macOS Seatbelt or network egress path, not by model cooperation.
- In-process: handler runs inside the Hermes Python process via `tools.registry.dispatch`, so it inherits all runtime privileges.

| Tool or tool family | ASF pre-tool interception | Real execution interception | Does DENY prevent execution? | Enforcement layer |
|---|---|---|---|---|
| `terminal` | `on_pre_tool_call` checks all tools at `asf_tracker_plugin.py` lines 492-554. Hermes honors block in `agent/tool_executor.py` lines 127-136, 180-183, 499-507, 589-592. | If `ASF_HERMES_SANDBOX=true`, dispatch wrapper replaces handler with `_sandbox_terminal` at lines 461-467. `_sandbox_terminal` runs `/bin/sh -c` through `run_sandboxed_process` at `asf_core.py` lines 506-517. | Yes in the normal live path, because Hermes skips execution after plugin block. If hook path is bypassed, only the Seatbelt profile can constrain syscalls, and only when sandbox is on. | Cooperative DENY always in current runtime path. OS/kernel confinement only for foreground non-PTY terminal subprocesses when `ASF_HERMES_SANDBOX=true` and `sandbox-exec` is available. Background and PTY terminal calls are rejected by ASF sandbox MVP at `asf_core.py` lines 506-508, but only if sandbox wrapper is used. |
| `execute_code` | Same pre-tool hook path as above. | If sandbox is enabled, dispatch wrapper replaces handler with `_sandbox_execute_code` at `asf_tracker_plugin.py` lines 467-468. It runs `[sys.executable, "-c", code]` through `run_sandboxed_process` at `asf_core.py` lines 520-525. | Yes in the normal live path, cooperatively. If bypassed, OS confinement applies only to the spawned Python subprocess when sandbox is enabled. | Cooperative DENY. OS/kernel confinement only for the subprocess under Seatbelt when enabled and available. |
| `read_file` | Same pre-tool hook path. Tool is normalized to `file_read` at `asf_tracker_plugin.py` lines 61-67 and `asf_core.py` lines 28-34. | No sandbox replacement. Dispatch wrapper calls original handler for non-terminal/non-execute_code tools at `asf_tracker_plugin.py` line 470. | Yes in the normal live path, because the runtime honors the block before dispatch. | Cooperative only. The file read happens in-process in the unconfined Hermes runtime via `tools.registry.dispatch` lines 390-405. Seatbelt profile does not apply. |
| `write_file` | Same pre-tool hook path. Normalized to `file_write` at `asf_tracker_plugin.py` lines 61-67. | No sandbox replacement. Original handler at dispatch line 470. | Yes in the normal live path. | Cooperative only. In-process file write is not Seatbelt-confined. |
| `patch` | Same pre-tool hook path. Normalized to `code_edit` at `asf_tracker_plugin.py` lines 61-67. | No sandbox replacement. Original handler at dispatch line 470. | Yes in the normal live path. | Cooperative only. In-process patch/edit is not Seatbelt-confined. |
| `search_files` | Same pre-tool hook path. Normalized to `file_search` at `asf_tracker_plugin.py` lines 61-67. | No sandbox replacement. Original handler at dispatch line 470. | Yes in the normal live path. | Cooperative only. In-process search is not Seatbelt-confined. |
| `process` | Not in ASF `TOOL_MAP`, but `on_pre_tool_call` still builds security text for unknown tools and uses the original tool name via `normalize_tool_name` fallback at `asf_core.py` lines 81-89. | No sandbox replacement. | Yes only cooperatively if ASF policy returns DENY and Hermes honors it. | Cooperative only. It can manage background processes started by Hermes tooling; ASF does not put those processes in a separate kernel domain unless they came from sandboxed terminal/code paths. |
| Browser tools, prefix `browser_*` | Prefix-normalized to `browser` at `asf_tracker_plugin.py` lines 81-83 and `asf_core.py` line 50. | No sandbox replacement. | Yes in normal path. | Cooperative only from ASF. Any browser process isolation is whatever Hermes/browser implementation provides, not ASF Seatbelt. |
| `web_search`, `web_extract`, `x_search` | `web_search` and `web_extract` are not in `TOOL_MAP`; unknown names fall through unchanged. | No sandbox replacement. | Yes in normal path if ASF policy denies. | Cooperative only. Network is from the Hermes runtime/tool implementation, not the Seatbelted tool subprocess path. The ASF egress proxy only protects sandboxed subprocesses configured to use it. |
| `memory`, `session_search`, `todo`, `skill_manage`, `skill_view`, `skills_list`, `cronjob`, `delegate_task`, `send_message`, `image_generate`, `text_to_speech` | Listed in `TOOL_MAP` at `asf_tracker_plugin.py` lines 61-79. `on_pre_tool_call` applies to them. | No sandbox replacement. Some agent-loop tools are handled before registry dispatch in `agent/tool_executor.py` lines 598-681, 714-727. | Yes in normal path because the agent loop checks the plugin before these special cases. | Cooperative only from ASF. |
| `clarify` | Not listed in ASF `TOOL_MAP`, but still reaches the pre-tool hook as an unknown tool. | Special-cased in agent loop at `agent/tool_executor.py` lines 656-663 after pre-hook. | Yes in normal path. | Cooperative only. |
| `kanban_*`, Discord, Feishu, Home Assistant, Spotify, Yuanbao, media/video/vision/MOA/computer_use and other registered live tools | Usually not listed in `TOOL_MAP`; unknown names fall through unchanged unless they match `browser_*`. The pre-hook still sees them. | No ASF sandbox replacement. They run through normal registry handlers or agent-loop special handling. | Yes only because Hermes honors the pre-hook block. | Cooperative only from ASF. Network/API side effects are not kernel-confined by ASF unless the tool's actual network calls are inside a sandboxed subprocess, which these are not. |

Current live registered tool names observed from the installed Hermes registry include: `browser_back`, `browser_cdp`, `browser_click`, `browser_console`, `browser_dialog`, `browser_get_images`, `browser_navigate`, `browser_press`, `browser_scroll`, `browser_snapshot`, `browser_type`, `browser_vision`, `clarify`, `computer_use`, `cronjob`, `delegate_task`, `discord`, `discord_admin`, `execute_code`, Feishu tools, Home Assistant tools, `image_generate`, `kanban_*`, `memory`, `mixture_of_agents`, `patch`, `process`, `read_file`, `search_files`, `send_message`, `session_search`, `skill_*`, Spotify tools, `terminal`, `text_to_speech`, `todo`, video/vision tools, web tools, `write_file`, `x_search`, and Yuanbao tools. ASF only has explicit category names for the subset in `TOOL_MAP` and the `browser_` prefix.

## 3. What the Seatbelt sandbox really covers

The sandbox profile itself says the key facts:

- `wrapper/asf_sandbox.sb` line 2: `sandbox-exec is deprecated by Apple`.
- Lines 3-4: it is an opt-in feasibility probe and `The Hermes runtime is not sandboxed. This profile applies to tool subprocesses only.`
- Lines 8-9: profile version and default deny.
- Lines 16-19: deny all network, then allow outbound only to `localhost:PROXY_PORT`.
- Lines 21-24: allow broad file reads. The comments explicitly say readable path policy is enforced before execution by the plugin, while Seatbelt enforces write confinement and proxy-only egress.
- Lines 33-34: writes are allowed only under `WORKDIR`.

`run_sandboxed_process` confirms this is per-process wrapping:

- `asf_core.sandbox_enabled()` reads `ASF_HERMES_SANDBOX`, default false, at lines 431-432.
- `sandbox_argv` inserts `sandbox-exec -D WORKDIR=... -D PROXY_PORT=... -f asf_sandbox.sb ...` at lines 448-469.
- If `sandbox-exec` is absent, it returns a blocked sandbox-unavailable result by default. The old unconfined fallback requires `ASF_HERMES_SANDBOX_ALLOW_UNCONFINED=true`, and `ASF_HERMES_SANDBOX_FAIL_CLOSED=true` overrides that opt-out.
- `run_sandboxed_process` then calls `subprocess.run(argv, ...)` with the sandbox argv at lines 486-496.
- Only `sandbox_terminal` and `sandbox_execute_code` call `run_sandboxed_process`, at lines 511-516 and 520-525.

The dispatch wrapper confirms only those two tools use this path:

- `asf_tracker_plugin.py` lines 461-469: if sandboxed and name is `terminal` or `execute_code`, use sandbox functions. Else call original dispatch at line 470.

The wrapper process does not sandbox Hermes itself:

- `wrapper/hermes_mvp.py` launches Hermes as `subprocess.call([hermes, *hermes_args], env=env)` at line 167. There is no `sandbox-exec` around the Hermes runtime process there.
- `build_env` only sets environment variables such as `ASF_HERMES_SANDBOX`, `ASF_HERMES_SANDBOX_WORKDIR`, and `ASF_EGRESS_PROXY_PORT` at lines 35-43 and 45-52.
- The egress proxy starts only when sandbox is enabled and `--net-allow` is present at lines 126-131.

The allowlist gate that used to be in the plugin is not active here. `asf_core.py` still has helper functions such as `is_command_allowed` at lines 297-305, `path_allowed` at lines 318-337, `network_allowed_for_text` at lines 361-368, and `allowlist_block_reason` at lines 371-388. In this inspected plugin, `on_pre_tool_call` does not call `allowlist_block_reason`; it only calls `asf_core.asf_decision` at `asf_tracker_plugin.py` lines 510-517. These helpers are therefore dead or legacy with respect to the current Hermes plugin allowlist gate, although `network_allowed_for_text` may still be useful as a shared helper elsewhere.

## 4. Network egress enforcement

There are two distinct mechanisms:

1. Intent-level inspection in ASF text.
   - `asf_core.network_allowed_for_text` parses URLs and checks `ASF_HERMES_NET_ALLOW` at lines 361-368. In the current plugin, the old allowlist block helper is not called, so this is not an active pre-tool gate from `on_pre_tool_call`.
2. Proxy-enforced egress for sandboxed subprocesses.
   - `asf_core.sandbox_env` sets `HTTP_PROXY`, `HTTPS_PROXY`, lowercase variants, and empties `NO_PROXY` if `ASF_EGRESS_PROXY_PORT` is set at lines 472-483.
   - `asf_sandbox.sb` denies all network then allows only outbound to `localhost:PROXY_PORT` at lines 16-19.
   - `asf_egress_proxy.EgressPolicy.decide` denies if the allowlist is empty or the host is not allowed at lines 92-98.
   - The proxy enforces this for HTTP CONNECT at lines 180-189 and plain HTTP at lines 197-219.

This is meaningful kernel-level egress confinement only for sandboxed tool subprocesses whose network syscalls are blocked except to the local proxy. It does not constrain the Hermes runtime process, in-process tools, or any code path that is not launched through `run_sandboxed_process`.

## 5. Bypass and threat-model analysis

Concrete current bypasses or non-guarantees:

1. Cooperative DENY depends on the hook being called and honored.
   - ASF returns `{"action": "block"}` from `on_pre_tool_call` only in enforce mode at `asf_tracker_plugin.py` lines 542-551.
   - Hermes skips execution because `agent/tool_executor.py` interprets the plugin result and synthesizes an error at lines 127-136, 180-183, 499-507, and 589-592.
   - If a future runtime path calls `registry.dispatch` directly without the pre-hook, imports handlers directly, disables plugins, changes the block result contract, or sets `ASF_HERMES_ENABLED=false`, the kernel will not stop most tools.

2. Fail-open behavior exists for ASF check failures unless explicitly configured.
   - `asf_core.asf_decision` sets verdict `ALLOW` on exception unless `ASF_HERMES_FAIL_CLOSED=true` at lines 183-187.
   - `register_hermes_agent` also swallows registration errors unless fail-closed is set at `asf_tracker_plugin.py` lines 345-347.

3. The Hermes runtime process is unconfined.
   - `hermes_mvp.py` line 167 launches Hermes directly, not under Seatbelt, container, VM, or other OS sandbox.
   - Plugin Python code, tool registry, model/provider code, memory/session access, and in-process tools inherit the user's full process privileges.

4. In-process file tools are not sandboxed.
   - Dispatch wrapper only replaces `terminal` and `execute_code` at `asf_tracker_plugin.py` lines 465-468.
   - `read_file`, `write_file`, `patch`, and `search_files` use original dispatch at line 470, and `tools.registry.dispatch` executes handlers in-process at lines 397-405.
   - The Seatbelt profile's write confinement at `asf_sandbox.sb` lines 33-34 does not apply to these in-process handlers.

5. `terminal` and `execute_code` are only kernel-confined under conditions.
   - `ASF_HERMES_SANDBOX` must be true (`asf_core.py` lines 431-432).
   - `sandbox-exec` must exist, otherwise ASF warns and runs unsandboxed unless `ASF_HERMES_SANDBOX_FAIL_CLOSED=true` (`asf_core.py` lines 448-454).
   - The sandbox MVP rejects background and PTY terminal only inside `sandbox_terminal` at lines 506-508. If sandbox is off, the original terminal tool behavior applies.

6. Seatbelt does not enforce read restrictions in the current profile.
   - `asf_sandbox.sb` allows `file-read*` broadly. Earlier versions passed a `READ_ALLOW` parameter, but the profile never consumed it and the parameter has been removed from the Hermes sandbox argv.
   - Therefore sandboxed terminal/code subprocesses can read broadly from the user's filesystem, subject to macOS privacy/TCC and normal Unix permissions, unless another mechanism intervenes. Writes are confined to `WORKDIR` by Seatbelt lines 33-34.

7. Network enforcement is partial.
   - The proxy exists only when the wrapper starts it, which requires sandbox not disabled and `net_allow` present at `hermes_mvp.py` lines 126-131.
   - The Seatbelt network rule applies only to sandboxed subprocesses (`asf_sandbox.sb` lines 16-19), not the Hermes runtime or in-process tools.
   - The proxy handles HTTP and HTTPS CONNECT. Raw TCP is blocked only because Seatbelt denies non-proxy outbound for sandboxed subprocesses. Without Seatbelt, a process could ignore proxy env vars.

8. Output risk detection is audit/visibility, not a kill switch.
   - The dispatch wrapper persists output and marks output risk at `asf_tracker_plugin.py` lines 409-437 and 557-558. This happens after execution in the `finally` block around dispatch at lines 472-485. It cannot prevent side effects that already occurred.

9. Special in-agent tool paths are still cooperative.
   - Agent-loop tools such as `todo`, `session_search`, `memory`, `clarify`, `delegate_task`, context-engine tools, and memory-manager tools are handled in `agent/tool_executor.py` after the pre-hook block logic, for example lines 598-681 and 714-727. They are protected only because the agent loop checks `_execution_blocked` first.

10. Policy can be bypassed by launching Hermes outside the wrapper or with different env.
   - `build_env` sets ASF variables at `hermes_mvp.py` lines 35-52, but a direct `hermes chat` launch depends on whatever plugin and environment configuration exists. `asf_core.sandbox_enabled` defaults false at lines 431-432.

Threat model conclusion: current ASF can stop honest Hermes tool calls in the current runtime path. It should not be described as a kernel-enforced kill switch for the agent process. The only kernel-enforced pieces are Seatbelt write and network restrictions for `terminal` and `execute_code` subprocesses under the sandbox-on path, with broad reads still allowed.

## 6. Gap summary

| Tool/threat | Current status | Kernel-enforced today? | Conditions for kernel enforcement |
|---|---|---|---|
| Pre-tool DENY/HITL for any tool | Cooperative plugin block | No | Would require moving enforcement outside Hermes or into an OS policy boundary that does not rely on Hermes honoring a return value. |
| `terminal` write side effects | Seatbelted only in ASF sandbox path | Yes, partially | `ASF_HERMES_SANDBOX=true`, `sandbox-exec` present, call is foreground non-PTY, and execution goes through ASF dispatch wrapper. Writes limited to `WORKDIR`. |
| `terminal` file reads | Broadly allowed in profile | No meaningful read confinement | Current profile allows `file-read*`. Need profile redesign or different isolation. |
| `terminal` network | Seatbelt plus proxy | Yes, partially | Sandbox on, proxy started, `ASF_EGRESS_PROXY_PORT` set. Raw network blocked by Seatbelt, HTTP/CONNECT domains enforced by proxy. |
| `execute_code` write side effects | Seatbelted only in ASF sandbox path | Yes, partially | Same as terminal, but for Python subprocess. |
| `execute_code` file reads | Broadly allowed in profile | No meaningful read confinement | Current profile allows broad reads. |
| `read_file` | In-process | No | Needs out-of-process broker or sandboxed runtime/container/VM. |
| `write_file` | In-process | No | Needs out-of-process broker or sandboxed runtime/container/VM. |
| `patch` | In-process | No | Needs out-of-process broker or sandboxed runtime/container/VM. |
| `search_files` | In-process | No | Needs out-of-process broker or sandboxed runtime/container/VM. |
| Browser/web/API tools | In-process or their own processes, not ASF sandboxed | No from ASF | Need whole-agent sandbox, per-tool subprocess isolation, network firewall/proxy at OS boundary, or VM/container boundary. |
| Runtime process compromise | Unconfined Hermes Python process | No | Need run Hermes inside sandbox/container/VM or enforce from host. |
| Direct handler import or dispatch bypass | Possible inside same Python process | No | Need deny at syscall boundary or make tools accessible only through a privileged broker that enforces policy. |

## 7. Options for true OS/kernel enforcement

### macOS on Apple Silicon M3

#### A. Continue with `sandbox-exec` as a probe

How DENY/KILL_SWITCH would be enforced:

- Wrap tool subprocesses or the entire Hermes process under a Seatbelt profile.
- Denied file/network/process operations fail at syscall/MAC policy boundary.

Pros:

- Already partially integrated for `terminal` and `execute_code`.
- Works on macOS without a Linux VM for simple subprocess constraints.
- Can enforce write confinement and network proxy-only egress for subprocess process trees.

Cons:

- `sandbox-exec` is deprecated by Apple, explicitly noted in `asf_sandbox.sb` line 2.
- Not a stable long-term thesis-grade production primitive.
- Current profile allows broad reads, so it is not confidentiality confinement.
- Hard to safely run a full Python agent with dynamic imports, Homebrew, provider SDKs, browser tooling, and user config under a restrictive Seatbelt profile without many allowances.
- Does not naturally support dynamic per-tool decisions after a process is already running.

Effort and fit:

- Low effort to improve the existing MVP for subprocesses.
- Medium to high effort to sandbox the whole Hermes runtime, with likely compatibility pain.
- Fit: acceptable as a feasibility probe, not a strong claim for durable kernel-level ASF enforcement.

Conceptual ASF changes:

- Fail closed if `sandbox-exec` is missing when sandbox mode is claimed.
- Remove broad file reads or split read-only mounts/allowances more narrowly.
- Run every side-effecting tool out-of-process, not just terminal/code.
- Stop describing plugin block as kernel enforcement.

#### B. macOS Endpoint Security Framework

How DENY/KILL_SWITCH would be enforced:

- A privileged Endpoint Security system extension subscribes to file, process, and network-ish events where available, and returns allow/deny decisions to the kernel for auth events.
- ASF policy would live in a daemon outside Hermes. Hermes would be just another monitored process.

Pros:

- Real OS-mediated authorization for supported event types.
- Can monitor a target process tree even if Hermes tries to bypass Python hooks.
- Better long-term Apple-supported direction than `sandbox-exec` for security products.

Cons:

- Requires a system extension, entitlements, codesigning, user approval, and often Apple developer program provisioning.
- Endpoint Security coverage is not a clean per-app sandbox. Network control is limited compared to a firewall/network extension design.
- Heavy for a thesis prototype and inconvenient for end users.
- Policy latency and event coverage need careful engineering.

Effort and fit:

- High effort.
- Fit: strong for a serious macOS security product, poor for a quick Python-only ASF wrapper.

Conceptual ASF changes:

- Move enforcement into a privileged host daemon.
- Tag Hermes process tree and enforce file/process/network policies by PID/code signature/path.
- Make plugin advisory only, with the daemon as the real decision point.

#### C. macOS App Sandbox

How DENY/KILL_SWITCH would be enforced:

- Package Hermes as a signed, sandboxed app with entitlements. macOS denies file/network/device access outside entitlements and user-selected security-scoped resources.

Pros:

- Apple-supported sandbox mechanism.
- Strong for packaged apps with known resource needs.

Cons:

- Poor fit for a CLI Python agent that dynamically launches shells, Python subprocesses, browsers, package managers, and arbitrary tools.
- Requires app packaging, signing, entitlements, and likely major UX changes.
- App Sandbox is entitlement/static-profile oriented, not a dynamic per-tool kill-switch policy engine.

Effort and fit:

- High effort, low fit for normal Hermes CLI workflows.

Conceptual ASF changes:

- Repackage Hermes as a macOS app or helper with strict entitlements.
- Move file access through user-selected/document-scoped locations or a broker.
- Treat terminal/code execution as separate sandboxed helpers.

#### D. Network Extension or PF firewall on macOS

How DENY/KILL_SWITCH would be enforced:

- Host-level firewall rules or a Network Extension blocks outbound connections except to an ASF proxy or allowlisted destinations.

Pros:

- Real network boundary independent of Hermes cooperation.
- Could protect runtime and in-process tools, unlike current proxy-only subprocess design.

Cons:

- PF requires root and careful rule lifecycle management. Network Extension requires entitlements and packaging.
- Does not solve filesystem/process confinement.
- Per-process policy on macOS is harder than container/VM networking.

Effort and fit:

- Medium to high.
- Fit: useful as one layer, not sufficient alone.

Conceptual ASF changes:

- Start a host policy component that pins Hermes process tree to proxy-only egress.
- Make all provider/tool network traffic go through proxy or deny at host firewall.

### Linux options, if Hermes runs in a Linux VM/container

#### A. seccomp-bpf

How DENY/KILL_SWITCH would be enforced:

- Kernel filters block syscalls such as `socket`, `connect`, `mount`, `ptrace`, risky `ioctl`, or process creation variants.

Pros:

- Mature, low-level, strong syscall boundary.
- Good for reducing attack surface of tool subprocesses.

Cons:

- Path-based file policy is not seccomp's strength.
- Python and browsers need many syscalls, so profiles can be noisy.
- Does not express domain allowlists by itself.

Effort and fit:

- Medium for subprocess profiles, high for whole Hermes plus browser.
- Fit: good combined with namespaces and Landlock.

Conceptual ASF changes:

- Launch tools through a supervisor that applies seccomp profiles before exec.
- For kill-switch, supervisor can refuse to exec or install filters that make prohibited syscalls fail.

#### B. Landlock

How DENY/KILL_SWITCH would be enforced:

- Unprivileged Linux Security Module lets a process restrict its own future filesystem access using path rules. Once restricted, the process cannot regain access.

Pros:

- Good fit for unprivileged filesystem confinement.
- Can give read/write rules per workdir and apply to tool subprocesses.

Cons:

- Linux-only and kernel-version dependent.
- A process must opt into restrictions before doing untrusted work.
- Network support is limited/new compared to filesystem.

Effort and fit:

- Medium.
- Fit: very good for file tools if they are moved out-of-process into a broker/worker model.

Conceptual ASF changes:

- Run file read/write/search/patch in workers that apply Landlock before handling requests.
- Make the broker the only path to host files.

#### C. Namespaces and cgroups

How DENY/KILL_SWITCH would be enforced:

- Mount namespaces expose only selected directories. Network namespaces remove network or route only through a proxy. PID/user namespaces isolate processes. Cgroups limit resources.

Pros:

- Strong primitive behind containers.
- Can confine complete process trees, including shells and Python code.
- Works well with bind mounts for workspace-only access.

Cons:

- macOS requires a Linux VM underneath.
- Complex to assemble securely by hand.
- Some tools need special handling for browser, Docker, SSH, credentials.

Effort and fit:

- Medium if using bubblewrap/nsjail/Docker, high if custom.
- Fit: excellent for Hermes tools, especially terminal/code/file tools.

Conceptual ASF changes:

- Supervisor launches Hermes or each tool worker inside namespaces.
- Use bind mounts for allowed reads/writes and a network namespace with only proxy route.

#### D. bubblewrap or nsjail

How DENY/KILL_SWITCH would be enforced:

- Wrapper creates namespaces, bind mounts, seccomp filters, and network restrictions around each tool process or the whole agent.

Pros:

- Practical composition of kernel primitives.
- Easier than raw namespaces/seccomp.
- Good for per-tool isolation.

Cons:

- Linux-only.
- Need careful profile design and compatibility testing.
- In-process file tools still need to be moved out-of-process or the whole runtime jailed.

Effort and fit:

- Medium.
- Fit: strong for a Linux VM-based ASF prototype.

Conceptual ASF changes:

- Replace macOS `sandbox-exec` path with a generic isolation runner interface.
- Implement Linux runner using bubblewrap/nsjail for terminal/code/file operations.

#### E. eBPF

How DENY/KILL_SWITCH would be enforced:

- eBPF programs observe or sometimes enforce kernel events through LSM hooks, cgroup hooks, or networking hooks.

Pros:

- Powerful observability and policy telemetry.
- Can enforce network policy with cgroup BPF in controlled deployments.
- Good for audit and anomaly detection around a process tree.

Cons:

- Complex, privileged, kernel-version dependent.
- eBPF is not a simple sandbox by itself. LSM BPF availability and policy semantics vary.
- Overkill for first kernel-enforced ASF milestone.

Effort and fit:

- High.
- Fit: later-stage monitoring/enforcement layer, not first step.

Conceptual ASF changes:

- Add host agent to attach policies to cgroups/processes.
- Use eBPF primarily for telemetry or network deny, while namespaces/Landlock provide file confinement.

### Isolation options

#### A. Docker/OCI container

How DENY/KILL_SWITCH would be enforced:

- Run Hermes inside a container with restricted bind mounts, read-only root filesystem, dropped capabilities, seccomp profile, no-new-privileges, cgroup limits, and controlled network.
- A DENY means the host-side wrapper does not perform an operation or the container kernel namespace does not expose the resource.

Pros:

- Practical and widely understood.
- Stronger than current plugin-only path.
- Easy to restrict filesystem via mounts and network via Docker network/proxy.
- Works on macOS through Docker Desktop's Linux VM.

Cons:

- On macOS, enforcement is inside Docker's Linux VM, not native macOS kernel over host files. Host bind mounts remain the bridge.
- Docker socket exposure would be catastrophic if mounted.
- Browser/UI and host integration need work.

Effort and fit:

- Low to medium for MVP.
- Fit: smallest viable real boundary for thesis claims if acceptable to run Hermes inside a container/VM.

Conceptual ASF changes:

- Launch the entire Hermes runtime inside a container by default for enforced mode.
- Bind mount only the workspace and explicit read-only inputs.
- Run ASF policy/proxy on host or sidecar, not inside the same trust boundary.
- Remove direct access to user home, SSH keys, cloud creds unless explicitly mounted.

#### B. gVisor

How DENY/KILL_SWITCH would be enforced:

- Container syscalls are intercepted by gVisor's user-space kernel, reducing host kernel exposure and enforcing container boundaries.

Pros:

- Stronger isolation than normal runc for many syscall attacks.
- Still uses OCI workflows.

Cons:

- Compatibility overhead. Browser and unusual tooling can break or slow down.
- On macOS still runs inside a VM stack.

Effort and fit:

- Medium.
- Fit: good second step after Docker if the thesis needs stronger isolation language.

Conceptual ASF changes:

- Support a runtime class for `runsc` and test tool compatibility.
- Keep same host-policy and mount/proxy model as Docker.

#### C. MicroVMs, Firecracker, Krun, Lima/Colima-style VMs

How DENY/KILL_SWITCH would be enforced:

- Run Hermes inside a minimal VM. The host exposes only selected shared directories and a controlled network interface/proxy. Kernel boundary is the guest/host VM boundary.

Pros:

- Strong isolation story. A compromised agent is contained in a guest.
- Clean host-as-policy-enforcement-point model.
- Better thesis-grade claim than a Python hook.

Cons:

- Firecracker itself is Linux-focused and not native macOS. On Apple Silicon, practical options are typically Virtualization.framework-backed VMs, Lima/Colima, or krun-like approaches, with varying maturity.
- More operational overhead than Docker.
- File sharing and interactive UX need design.

Effort and fit:

- Medium to high.
- Fit: best defensible direction for macOS M3 if the user accepts running Hermes in a Linux VM with the macOS host as controller.

Conceptual ASF changes:

- Host ASF launcher creates an isolated VM per session or project.
- Hermes runs inside guest with no direct host home access.
- Host broker handles file exchange, policy decisions, snapshots, and network proxying.

#### D. Host broker with untrusted worker model

How DENY/KILL_SWITCH would be enforced:

- Hermes no longer directly performs side effects. It sends requests to a separate broker. The broker enforces policy and executes actions in sandboxed workers or refuses.

Pros:

- Clean security architecture.
- Eliminates direct in-process file write/search/read bypasses.
- Can combine with container/VM isolation per worker.

Cons:

- Requires significant refactor of tool execution model.
- Must secure broker API, auth, request schemas, and path normalization.

Effort and fit:

- High for full coverage, medium for file tools first.
- Fit: strong long-term ASF architecture.

Conceptual ASF changes:

- Convert file tools and shell/code tools into RPC calls to host-enforced workers.
- Make `registry.dispatch` incapable of direct host side effects in enforced mode.
- Treat plugin hook as policy UX/audit, not the trusted enforcement point.

## 8. Recommendation

### Phase 0: Claim accurately now

What to claim:

- ASF provides cooperative pre-tool enforcement integrated into the Hermes runtime.
- In enforce mode, DENY/HITL prevents execution in the inspected live runtime path because Hermes checks `get_pre_tool_call_block_message` before dispatch and returns a synthetic error instead of executing.
- ASF has a prototype macOS Seatbelt sandbox for `terminal` and `execute_code` subprocesses. When enabled and available, it kernel-enforces write confinement to `WORKDIR` and proxy-only network egress for those subprocesses.

What not to claim:

- Do not claim ASF currently confines the Hermes agent at kernel level.
- Do not claim the kill-switch is unbypassable if Hermes or plugin paths change.
- Do not claim network egress is globally enforced for the runtime or all tools.
- Do not claim read confinement from the current Seatbelt profile, because `file-read*` is broadly allowed.

### Phase 1: Smallest viable hardening step

Smallest practical step for a defensible improvement:

Phase 1 implementation status: sandbox-on subprocess execution now fails closed by default if `sandbox-exec` is unavailable. The old unconfined fallback is available only with the explicit development opt-out `ASF_HERMES_SANDBOX_ALLOW_UNCONFINED=true`, unless `ASF_HERMES_SANDBOX_FAIL_CLOSED=true` is also set. The Seatbelt profile and wrapper output now state the scope plainly: subprocesses routed through the sandbox runner get write confinement to `WORKDIR`; network is proxy-only when the proxy is configured; reads are not confined; the Hermes runtime itself is not sandboxed.

1. Make enforced sandbox mode fail closed if `sandbox-exec` is absent.
   - `asf_core.sandbox_argv` now refuses to execute unconfined by default when `sandbox-exec` is unavailable.
2. Be explicit in CLI output and docs that sandbox applies only to `terminal` and `execute_code` subprocesses.
3. Keep the LangGraph allowlist helpers because `wrapper/langgraph_mvp.py` still calls `allowlist_block_reason`; the Hermes plugin path does not use them.
4. Tighten the Seatbelt profile if confidentiality matters, especially replacing broad `file-read*` with a realistic read allow strategy. If compatibility requires broad reads, document that reads are not confined.

This still would not be whole-agent confinement, but it would make the current subsystem honest and fail-closed.

### Phase 2: Move file tools out-of-process

Phase 2 implementation status: `read_file`, `write_file`, `patch`, and `search_files` are routed through `run_sandboxed_process` when `ASF_HERMES_SANDBOX=true` and `ASF_HERMES_SANDBOX_FILE_TOOLS` is enabled. The flag defaults to enabled and can be set to `false` to restore native in-process dispatch while the sandbox remains on. If `sandbox-exec` is unavailable while sandboxing is requested, these file tools fail closed with the same blocked result shape used by Phase 1 instead of falling back to in-process execution.

The security gain is specific: writes are confined to `WORKDIR` by Seatbelt and by explicit worker path checks, file tools no longer execute inside the unconfined Hermes runtime, and all sandboxed tool subprocesses share one runner choke point. Reads remain broad under the current profile because `(allow file-read*)` is still present.

This closes the previous biggest mismatch for file writes. It is still not whole-agent confinement, and it is not a read-confidentiality boundary.

### Phase 3: Container or VM enforced mode

For a thesis-grade kernel boundary on macOS M3, the most realistic defensible path is:

- Run Hermes inside a Linux VM or OCI container with only the project workspace mounted.
- Put ASF policy/proxy/broker on the host side or in a more trusted sidecar.
- Enforce network by container/VM network policy so all egress must go through the ASF proxy.
- Enforce file access by mounts, read-only roots, and no home-directory bind mount by default.
- Drop capabilities, apply seccomp, no-new-privileges, and resource limits.

This gives a clear statement: even if the agent ignores the Python plugin, the guest/container cannot access host paths or network destinations that were not exposed by the host.

### Phase 4: Long-term architecture

- Adopt a host broker model for all side effects.
- The Hermes runtime can propose actions, but the broker decides and executes in isolated workers.
- Add Endpoint Security or Network Extension only if native macOS product-grade enforcement is a goal. For a research prototype, a Linux VM/container boundary is much faster and more defensible.

Final assessment

ASF today is a cooperative enforcement and audit layer with a limited subprocess sandbox. It is valuable and blocks real tool calls in the inspected Hermes path, but its security guarantee is conditional on runtime cooperation. True kernel/OS confinement requires moving the trust boundary outside the Hermes Python process: either run the whole agent in a restricted container/VM, or route all side-effecting tools through a broker that applies OS sandboxing before execution. On macOS, `sandbox-exec` can support a probe, but the most credible path for robust enforcement on Apple Silicon is a Linux VM/container or host-broker architecture, not relying on a Python plugin hook as the kill-switch.
