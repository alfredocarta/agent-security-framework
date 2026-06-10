# Phase 3: Host-Enforced Container Boundary

## 1. Summary

Phase 3 runs the entire Hermes agent (the runtime, its in-process tools, and every subprocess it spawns) inside a Linux container whose boundary is enforced by the host, not by cooperative code inside the agent. The host (macOS) keeps the ASF policy, the egress proxy, and the launcher outside the container. The container gets no host access except one explicitly bind-mounted workspace directory. This is a different trust model from the current cooperative plugin plus per-subprocess Seatbelt: there, a bypass of the in-process checks reaches the real host filesystem and network; here, a full bypass of the in-container plugin still cannot reach any host path or network route that the host did not expose.

This document describes the trust boundary, what is enforced and how, how a DENY or kill-switch is backed by the boundary, and an honest account of what is not covered. The prototype that implements it is Dockerfile.phase3, wrapper/asf_container_launch.py, wrapper/asf_phase3_seccomp.json, and the Docker-gated smoke test tests/test_container_sandbox.py.

## 2. Current state and why it is not enough

Today ASF confines Hermes with four cooperative or partial layers. The ASF plugin (integrations/hermes/asf_tracker_plugin.py) intercepts tool calls in-process and can veto them, but it runs inside the same process it is trying to constrain, so a compromised or buggy runtime can bypass it. The file worker (wrapper/asf_file_worker.py) performs file operations out of process with confinement checks. The egress proxy (wrapper/asf_egress_proxy.py) applies a domain allowlist, but only to traffic that is actually routed through it. The macOS Seatbelt profile (wrapper/asf_sandbox.sb) sandboxes terminal and execute_code subprocesses launched via sandbox-exec, but not the main Hermes process or its in-process tools.

The gap is that filesystem and network boundaries are enforced in userspace and only on the cooperating paths. The Hermes runtime itself is not sandboxed, and any code path that does not go through the plugin, the file worker, or sandbox-exec runs with the full ambient authority of the user account that launched Hermes (home directory, SSH and cloud credentials, the whole network). Phase 3 closes that gap by moving the boundary to the OS and applying it to the whole agent process tree at once.

## 3. Trust boundary

```
+-------------------------------------------------------------------+
|                           HOST (macOS M3)                         |
|   ASF policy + launcher (wrapper/asf_container_launch.py)          |
|   - builds the run with confinement flags                         |
|   - owns the workspace bind mount                                 |
|   - can always `docker kill` the container                        |
|                              |                                    |
|                              | docker run (hardened)              |
|                              v                                    |
|   +-----------------------------------------------------------+   |
|   |          Docker Desktop Linux VM (kernel boundary)        |   |
|   |                                                           |   |
|   |  internal network (no external route)   external network  |   |
|   |   +-------------------------+        +------------------+  |   |
|   |   | Hermes + ASF plugin     |        | ASF egress proxy |  |   |
|   |   | (enforce mode)          |--only--| sidecar          |--> internet
|   |   | read-only root fs       |  path  | (asf_egress_     |  |   |
|   |   | /workspace bind (rw)    |  out   |  proxy.py)        |  |   |
|   |   | cap-drop ALL, seccomp   |        | allowlist +      |  |   |
|   |   | no-new-privileges, uid  |        | host map         |  |   |
|   |   | 1000, cpu/mem/pid caps  |        +------------------+  |   |
|   |   +-------------------------+                              |   |
|   +-----------------------------------------------------------+   |
+-------------------------------------------------------------------+
```

The Hermes container sits on a Docker network created with --internal, which has no route to anything outside that network. The only neighbour it can reach is the ASF egress proxy sidecar, which is attached to both the internal network and an external network. The sidecar runs the same wrapper/asf_egress_proxy.py used elsewhere, so the allowlist and host-map semantics are identical. Everything the Hermes container sends to the outside world passes through that proxy, and the proxy applies the policy.

## 4. What is enforced and how

### 4.1 Filesystem confined to the workspace

The project directory is bind-mounted read-write at /workspace and is the only bind mount. There is no home mount, no ~/.ssh, no ~/.aws or other cloud credentials, and critically no /var/run/docker.sock. The container root filesystem is mounted read-only, and /tmp, /var/tmp, and the non-root user cache directory are tmpfs (noexec, nosuid, size-capped). The effect is that the container can write only under /workspace and into ephemeral tmpfs. Any host path that was not bind-mounted does not exist inside the container, and the read-only root prevents writing anywhere else. The launcher flags are:

```
--read-only
--tmpfs /tmp:rw,noexec,nosuid,size=64m
--tmpfs /var/tmp:rw,noexec,nosuid,size=16m
--tmpfs /home/asf/.cache:rw,noexec,nosuid,size=64m
-v <workspace>:/workspace:rw
```

### 4.2 Network forced through the ASF egress proxy

The Hermes container runs on the --internal network, so the Docker VM kernel gives it no route to the internet or to the host. The ASF egress proxy sidecar is the single bridge between the internal network and the outside. The launcher also sets HTTP_PROXY, HTTPS_PROXY, and their lowercase variants to the sidecar so well-behaved clients use it directly. The important property is that even a process that ignores those environment variables and opens a raw socket to a public address cannot reach it, because the internal network has no route. Direct egress is denied by the kernel, not by the proxy, and the proxy is where the allowlist decision is made for the traffic that does get out.

### 4.3 Privilege reduction

The container drops all Linux capabilities (--cap-drop ALL) and adds none back. It runs with --security-opt no-new-privileges:true so a setuid binary cannot raise privileges, runs as the non-root user uid:gid 1000:1000, and applies a seccomp profile (wrapper/asf_phase3_seccomp.json). The seccomp profile is a deny-list with a permissive default. This is deliberate: the Apple Silicon Docker VM runs arm64 containers, and an allow-list default-deny profile that only lists x86_64 syscalls (as the one in sandbox.py does) blocks every syscall on arm64 and prevents the container from starting. The deny-list removes the most dangerous kernel surface (module loading, kexec, ptrace, mount and namespace manipulation, swap control, clock changes, perf, bpf, keyring) while remaining architecture-agnostic. A stricter per-architecture allow-list profile is future work.

### 4.4 Resource limits

The container is launched with --pids-limit 256 to stop fork bombs, --memory 1g with matching --memory-swap so memory cannot be exceeded via swap, and --cpus 2. A runaway agent inside the container cannot starve the host.

## 5. How a DENY or kill-switch is backed by the boundary

Today the kill-switch sets a suspension flag that the in-process plugin checks on each call. If the plugin is bypassed, the suspension is not enforced and the agent keeps acting with full host authority.

Under Phase 3 the enforcement does not depend on the agent cooperating. The plugin still runs inside the container in enforce mode and still produces audit events and DENY decisions on the cooperative path, which is the normal, fast case. But the boundary is what makes a bypass safe: even if the in-container plugin is disabled or defeated, the container cannot reach any host path that was not bind-mounted and cannot open any network route except through the ASF egress proxy, which applies the allowlist independently of anything inside the container. A hard kill is a host action: the launcher, which is outside the container and holds no Docker socket inside it, can always run docker kill or docker stop, and the container has no way to prevent its own termination because it cannot reach the Docker API. The container is treated as a confined execution environment, not as a trusted participant in its own confinement.

## 6. Honest limitations

The kernel boundary on macOS is the Docker Desktop Linux VM, not the macOS kernel directly. Containers are isolated by the VM kernel. A container escape would land in the Linux VM, and only a second VM escape would reach macOS, but the boundary should be described as VM-backed, not bare-metal.

The workspace bind mount is a real bridge. Whatever lives in the mounted project directory is readable and writable by the container, so if the project directory itself contains secrets (a committed .env, tokens, private keys), the agent can read them. Keep secrets out of the workspace, or mount narrower subdirectories.

The Docker socket must never be mounted into the container. If /var/run/docker.sock were exposed, the container could create new privileged containers and escape to the host. The launcher never mounts it and the design depends on that invariant.

Egress is only as good as the proxy policy. The internal network guarantees the proxy is the only path out, but the allowlist is what decides which destinations are reachable. An over-broad allowlist or a permissive host map weakens this. The HTTP_PROXY environment variables are defence in depth for cooperative clients, not the control itself; the control is the internal network.

Host environment variables can leak into the container if passed explicitly. The launcher sets only ASF and proxy variables and does not forward the host environment, but anyone extending it should avoid passing the ambient environment.

Credentials, browser automation, and GUI tooling are not covered. Any feature that needs the host keychain, an X11 or display socket, a real browser profile, or device passthrough would require additional mounts or sockets, and each such addition is a new hole in the boundary that must be justified separately. None of those are mounted here.

The seccomp profile is a pragmatic deny-list, not a minimal allow-list, for the arm64 reason given above. It reduces attack surface but is less strict than a tailored allow-list would be.

## 7. Stronger isolation options (not required for the MVP)

For a true kernel boundary on macOS rather than a shared Docker VM, a microVM or per-workload VM gives stronger isolation. Lima can run a dedicated Linux VM per workload. QEMU or KVM provides full virtualization with a custom kernel. Firecracker provides microVMs designed for fast, isolated, short-lived workloads. gVisor (runsc) and Kata Containers slot in as container runtimes that put a stronger boundary under each container. All of these are heavier to operate than plain Docker and are out of scope for this prototype, which targets Docker Desktop on the developer machine.

## 8. Prototype and verification

The prototype consists of Dockerfile.phase3 (a minimal image carrying the ASF framework and the egress proxy code, run as a non-root user), wrapper/asf_container_launch.py (the opt-in launcher that creates the internal and external networks, starts the egress proxy sidecar, and runs Hermes with all the confinement flags above in enforce mode), wrapper/asf_phase3_seccomp.json (the seccomp profile), and tests/test_container_sandbox.py (the Docker-gated smoke test).

The launcher is opt-in and entirely separate from wrapper/hermes_mvp.py; the existing non-container wrapper, plugin, file worker, and Seatbelt paths are unchanged. The Hermes runtime binary is not baked into the image; supply it by mounting a prebuilt runtime read-only at ASF_HERMES_AGENT_ROOT or by extending the image. The boundary the launcher applies is independent of how Hermes is provided.

The smoke test skips cleanly when no Docker daemon is reachable, matching the pattern in tests/test_sandbox.py, so the full suite stays green without Docker. When Docker is available it proves three properties against a container launched with the real production flags: a write to a host path outside the mounted workspace is impossible (the unmounted path is absent and the root filesystem is read-only); direct egress to a non-proxy host fails while egress through the ASF proxy to an allowed host succeeds and a denied host is refused with HTTP 403; and a normal in-workspace tool call (write then read a file under /workspace and import an ASF module from PYTHONPATH) succeeds. These three were run and passed on the Apple Silicon Docker Desktop VM during development.
