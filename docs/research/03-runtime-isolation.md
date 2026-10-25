# 03 — Runtime Isolation for the Workload

> [!NOTE]
> Status: **research note, DRAFT** (2026-10-24). This note ranks below accepted ADRs and specifications.
> Nothing here has been executed yet: **every containment claim is NOT TESTED** until the probes
> in §7 run against a real deployment and the results are recorded in `STATUS.md`.

Marking convention:

- **[F]** established fact, primary source fetched and checked on 2026-10-24 (reference number given).
- **[F\*]** established fact from a primary source that was **not** re-fetched for this note; check it before relying on it.
- **[H]** hypothesis or engineering judgement, not yet verified.
- **[V]** hypothesis that a named probe in §7 is designed to confirm or refute.

## 1. Goal and scope

An attacker with arbitrary code execution inside the application process (threat actors C, D, and H
in the owner directive) must find **no network route, socket, file, IPC endpoint, or credential**
that reaches a protected resource, other than the broker's request interface (SI-01, SI-02), and
protected resources must reject everyone except the broker (SI-03). The attacker must also be unable
to read or change broker policy, keys, or configuration (SI-13), or to tamper with the broker process.

Out of scope (consistent with `SECURITY_INVARIANTS.md`): actors I (host or container-manager compromise)
and J (broker or Authority compromise). Host-kernel exploits are the main **residual** risk, and §4
and §6 say how each architecture handles them. They are not assumed away silently.

Isolation decides **which paths exist**. It does not decide **what the broker lets the caller do**
over the one path that remains (SI-05..SI-16). This note covers only the first question.

## 2. Mechanism findings

### 2.1 Docker networks

- **`internal: true` does not mean "no reachability".** Docker's reference says containers on an
  internal network "may communicate between each other, but not with any other network", with no
  default route and firewall drop rules. It also says: "Communication with the gateway IP address
  (and thus appropriately configured host services) is possible", and "the host may communicate
  with any container IP directly" [F, 1]. So any host service listening on the bridge gateway address,
  or on `0.0.0.0`, is reachable from an "internal" container.
- **DNS has been an exfiltration path out of internal networks.** CVE-2024-29018: `dockerd`'s
  embedded resolver forwarded queries from internal networks to external nameservers through the
  host's namespace, which allowed data exfiltration over DNS. It was fixed in Moby 26.0.0, 25.0.4,
  and 23.0.11, and later releases adjusted the internal-network resolver behaviour (26.1.3) [F, 2].
  Lesson: the routing table alone does not define reachability, because daemon-side proxies (DNS,
  userland port proxy) act as deputies.
- **Inter-container traffic.** By default, containers on the same user-defined network "effectively
  expose all ports to each other". `com.docker.network.bridge.enable_icc` can turn this off [F, 3].
  A container attached to two networks bridges them at layer 7 if it runs anything that forwards.
- **`network_mode: none`** gives the container its own network namespace with only loopback [F\*, 4].
  No IP path exists, so gateway exposure, DNS forwarding, ICC, and metadata endpoints all disappear
  at once. This is the property P0 builds on (§6).
- Docker also turns on host IP forwarding and installs a default drop policy for forwarded packets,
  unless `ip-forward-no-drop` is set [F, 5]. Operators who edit host firewall rules can silently
  defeat network isolation. That is why P0 avoids depending on bridge firewall rules for the workload.

### 2.2 Privilege reduction inside the container

- **Capabilities.** Docker keeps a reduced default set. `cap_drop: [ALL]` removes the rest,
  including `CAP_NET_RAW` (raw and ICMP sockets) and `CAP_SETUID`/`CAP_SETGID` [F, 6].
- **`no-new-privileges`** sets `PR_SET_NO_NEW_PRIVS`. After that, setuid binaries and file
  capabilities cannot raise privileges across `execve` [F\*, 7].
- **Default seccomp profile.** It is an allowlist that returns an error for everything else and
  "disables around 44 system calls out of 300+". These include namespace creation (except user
  namespaces), `mount`, `keyctl`/`add_key`, `bpf`, `userfaultfd`, module loading, `kexec_load`,
  `perf_event_open`, and `io_uring_*` ("due to security vulnerabilities that can be exploited to
  break out of containers"). It also restricts `socket(AF_ALG / AF_VSOCK)` [F, 8].
  `seccomp=unconfined` removes all of this [F, 8].
- **seccomp user notification must not enforce policy.** `seccomp_unotify(2)`: "this mechanism
  must not be used to make security policy decisions about the system call", because "there is a
  time-of-check, time-of-use race" [F, 9]. The owner directive also forbids it. PBE uses seccomp only
  in its kernel-decided `ERRNO`/`KILL` forms.
- **User namespaces.** The Docker daemon supports remapping container root to an unprivileged host
  UID, but "This facility is available but not enabled by default" [F, 6]. Rootless Docker runs the
  daemon and containers inside a user namespace, so a daemon or runtime compromise lands on an
  unprivileged user instead of host root [F, 10]. Podman is rootless by default, and Podman 5 uses
  `pasta` for rootless networking [F\*, 11]. Kubernetes exposes per-pod user namespaces through
  `hostUsers: false` [F\*, 12]. Check the feature's maturity in the target cluster version.
- **Read-only rootfs** (`read_only: true`) plus `tmpfs` mounts with `noexec,nosuid,nodev` remove
  persistence and writable code paths. This does not stop in-memory execution by an interpreter
  (PHP `eval`), which is exactly threat C. Read-only filesystems are hygiene, not containment of
  authority [H].
- **AppArmor / SELinux.** Docker applies `docker-default` on AppArmor hosts, and `container_t`
  labelling on SELinux hosts with SELinux enabled. Both are MAC layers that restrict mounts, writes
  under `/proc` and `/sys`, and cross-container file access [F\*, 13, 14]. Which one is active depends
  on the host distribution. A `verify` tool must report what is actually enforced, not what is
  configured [V: K-02].

### 2.3 Landlock

Landlock is an unprivileged, stackable LSM that a process applies to itself and its descendants.
ABI history from the kernel documentation [F, 15]:

| ABI | Adds |
|---|---|
| 1 | Filesystem access rights (Linux 5.13) |
| 2 | `REFER` (cross-directory link/rename) |
| 3 | `TRUNCATE` |
| 4 | **TCP** `bind`/`connect` restriction by port |
| 5 | `IOCTL_DEV` |
| 6 | Scoping of **abstract UNIX sockets** and signals |
| 7 | Audit logging controls |
| 8 | `TSYNC`, ruleset applied to all threads |
| 9 | `RESOLVE_UNIX`, pathname UNIX sockets |
| 10 | **UDP** bind/connect/send |
| 11 | `RESTRICT_SELF_NO_NEW_PRIVS` |

The fetched document does not map ABIs 2–11 to kernel releases. The commonly cited mapping (ABI 4 =
Linux 6.7, ABI 6 = 6.12) is [F\*]. Limits that matter for PBE [F, 15]: network rules are **port-based
only** (no destination address), and only TCP and, from ABI 10, UDP are covered. Sockets reachable
through `/proc/<pid>/fd/*` "cannot currently be explicitly restricted". Scoping has no exceptions.

Assessment [H]: Landlock is a useful **inner** layer that a PBE launcher could apply to the PHP
process, for example to deny all TCP connect and limit files to the docroot. It cannot be the
**primary** network boundary, for three reasons: it has no address rules, it depends on the kernel
ABI available, and it is opt-in by the process (the launcher, not the app, must apply it before
`exec`). On a kernel that has it, ABI ≥ 6 is worth requiring, because abstract UNIX sockets are
otherwise a cross-container channel whenever containers share a network namespace.

### 2.4 Stronger sandboxes

- **gVisor (runsc).** Threat model: untrusted code trying to exploit **host kernel** bugs. The Sentry
  implements the Linux API in Go (no CGo), "No system call is passed through directly to the host",
  and the Sentry itself uses a small host syscall set. It generally cannot open host files or
  create host sockets unless host networking or directfs is enabled. Out of scope: hardware side
  channels and resource exhaustion (left to cgroups). It also says "Network policy controls should
  be applied at the container level" and "A sandbox is not a substitute for a secure architecture"
  [F, 16]. Compatibility: releases are regression-tested against Python, Java, Node.js, PHP, and Go
  runtimes. `io_uring` is off by default, and iptables/nftables support is partial [F, 17].
  arm64 is supported [F\*, 17], and the systrap platform does not need KVM [F\*, 18].
- **Kata Containers / Firecracker.** Each sandbox gets its own guest kernel inside a KVM microVM.
  Firecracker's design treats the guest as fully untrusted, adds a `jailer` around the VMM, and keeps
  a minimal device model [F\*, 19, 20]. Both need `/dev/kvm`, and therefore **nested virtualisation**
  inside Colima (§8).
- **gVisor and microVMs reduce the *kernel* part of the TCB, not the *network* part.** Inside them,
  the same reachability rules (no route, no credential) still have to be configured [F, 16].

### 2.5 Cloud metadata endpoints

On cloud hosts, `169.254.169.254` (and `[fd00:ec2::254]` on AWS when enabled) serves instance
credentials. AWS recommends IMDSv2-only (`httpTokens=required`) and lets operators set the PUT
response hop limit or turn the endpoint off [F, 21]. A hop limit of 1 is the usual mechanism that keeps
bridged containers from getting an IMDSv2 token [F\*, 22]. Under P0 the workload has no route at all,
so this is defence in depth. **The broker's** network still needs metadata blocked, or the broker
ends up holding cloud credentials it does not need.

### 2.6 Broker channel and caller authentication

- **UNIX-domain socket (UDS) vs TCP.** A pathname UDS is reachable only by processes that can resolve
  the path in their mount namespace and have write permission on the socket inode. So **mounting
  the socket into one workload only** makes the mount the capability: a per-workload socket
  authenticates by construction [H]. TCP needs a network path, which reintroduces everything in §2.1.
- **Abstract UNIX sockets** have no permission model ("Socket permissions have no meaning for abstract
  sockets") [F, 23]. They are scoped per network namespace [F\*, 23]. PBE must never use them for the
  broker, and the workload must not share a network namespace with the broker or the DB.
- **`SO_PEERCRED`** returns the peer's credentials "in effect at the time of the call to connect(2),
  listen(2), or socketpair(2)" [F, 23]. Across containers, the PID is translated relative to the
  reader's PID namespace (0 if not visible) and UID/GID through user-namespace mappings [F\*, 23].
  So it can confirm "the peer is UID 10001 in the expected mapping". It cannot say which container
  the peer is in. Per-workload sockets supply that.
- **mTLS / SPIFFE** fit multi-host or Kubernetes deployments. In-workload keys there are **identity**,
  not **authority**: stealing them from inside the workload gives the attacker exactly the identity
  it already has [H]. They add parsing and PKI to the TCB, with no gain on a single host.
- **Docker socket.** Docker says "only trusted users should be allowed to control your Docker daemon".
  Its example is that a container can be started with the host `/` mounted [F, 6]. TLS client keys
  give "root access to the machine hosting the daemon" [F, 24]. Any path from the workload to
  `docker.sock`, `containerd.sock`, a Docker TCP port, or the Colima/Lima control sockets is a
  complete break of every invariant.

## 3. Architectures

- **A. Conventional app under OS isolation, plus an external broker.** Unmodified PHP-FPM, Node, or
  Python runs in a hardened container (optionally gVisor or a microVM). Protected effects go through
  a broker in a separate container with separate credentials.
- **B. Capability-native runtime (WASI / Wasmtime).** The app is compiled to (or its interpreter runs
  as) a Wasm component. The host grants only the imports it chooses: preopened directories,
  `wasi:sockets` if allowed, and a custom `pbe:broker` interface. There is no ambient authority.
- **C. Hybrid.** Architecture A as the outer boundary. Optionally Wasm inside for new code or plugins
  (Native Effect Authorization mode), and Wasm for broker-side extensions.

### 3.1 State of language runtimes on WASI (October 2026)

- The WASI 0.3 toolchain snapshot was still a release candidate (`0.3.0-rc-2026-03-15`). The language
  table advises targeting WASI 0.2 for non-Rust toolchains [F, 25].
- **Python:** componentize-py targets WASI 0.2 components. CPython's own WASI support is listed as
  "implementation in progress" [F, 25]. No `fork`/`subprocess`, and C extensions must be rebuilt for
  wasm [F\*].
- **JavaScript:** jco/componentize-js (StarlingMonkey engine) produce components on WASI 0.2, with
  experimental 0.3 support [F, 25]. This is not Node.js: npm packages that use Node built-ins
  (`net`, `fs` semantics, native addons) do not run unchanged [F\*].
- **PHP:** not listed on wasi.dev [F, 25]. A wasm32-wasi PHP port exists from VMware Wasm Labs, and
  early versions could not use server-side sockets [F, 26]. WordPress Playground's `php-wasm`
  supports PHP 7.4–8.5, but its Node networking needs a WebSocket-to-TCP proxy, and it is an
  Emscripten/JS-host build rather than a WASI capability model [F, 27]. I found no maintained,
  production-grade PHP-on-WASI distribution with PDO drivers, `pcntl`, or the common extensions [H].

Conclusion [H]: architecture B is **not viable for Legacy Containment of PHP in 2026**. Rewrites or
porting of the interpreter and extensions would be required, which contradicts "legacy".

### 3.2 Comparison

Ratings are relative engineering judgements [H]. None of them is a measurement.

| Criterion | A: OS isolation + broker | B: WASI/Wasmtime | C: Hybrid (A outer, Wasm inner) |
|---|---|---|---|
| **Path containment (SI-01)** | Strong when the workload has `network_mode: none` + UDS. It depends on a correct container config, and config errors are the main failure mode. | Strong by construction: no import means no capability. It depends on the host embedding granting nothing extra. | Strongest: two independent layers, each sufficient for SI-01 on its own. |
| **Credential custody (SI-02)** | Broker-only secrets. The workload environment and filesystem must be audited (probe F-01). | Same. Easier to audit, because the WASI environment is explicit. | Same as A. |
| **TCB** | Host kernel (full syscall surface, reduced by seccomp), runc, dockerd/containerd, broker. Large but heavily scrutinised. gVisor swaps most host-kernel exposure for the Sentry. | Wasmtime (Cranelift codegen and runtime), the host embedding, and the host kernel under the Wasmtime process. Smaller interface, but a JIT compiler is in the TCB, and Wasmtime has had sandbox-escape-class advisories (e.g. CVE-2023-26489, x86_64 codegen) [F\*, 28]. | Both. The *effective* barrier is whichever layer the attacker must break last. |
| **Bypass resistance** | Kernel 0-day → escape. Mitigations: seccomp, user namespaces, gVisor/microVM. | Wasm-runtime bug → host process, which then still sits under OS isolation if you deploy that way (i.e. C). | An attacker needs two independent bugs. |
| **PHP compatibility** | Full (unmodified PHP-FPM). | Poor (see 3.1). | Full for legacy, Wasm only for new modules. |
| **Node compatibility** | Full; gVisor regression-tested [F, 17]. | Partial: JS engines, not Node. | Full. |
| **Python compatibility** | Full; gVisor regression-tested [F, 17]. | Partial: pure-Python plus rebuilt extensions. | Full. |
| **Ops complexity** | Low with Compose. Medium with rootless or gVisor. Higher with microVMs (KVM required). | Custom host, custom packaging, immature debugging and observability. | Highest, so defer. |
| **Performance** | runc ≈ native [H]. gVisor adds syscall and I/O overhead [F\*, 18]. microVMs add boot and memory overhead [F\*, 19]. | Interpreter-in-Wasm costs unmeasured for PHP [H]. | Sum of both. |
| **Verifiability** | Moderate: many knobs, so external probes are needed (§7). | High: the authority is the import list, so a static manifest is close to complete [H]. | Moderate. |

**Recommendation [H]:** use **A** for the PoC and for Legacy Containment, delivered as Deployment Profile
P0 (§6). Offer P1 (A + gVisor) as the hardened profile against kernel exploits. Keep **B/C** as
Phase-7 research for Native Effect Authorization, where a `pbe:broker` WIT interface is the cleanest
possible expression of "the broker is the only capability".

## 4. Q2 — Is OS isolation sufficient for legacy apps?

**Sufficient for path containment, not for authority semantics, and only if the app gives up its
direct protected-resource access.**

- OS isolation can make SI-01/SI-02/SI-03/SI-13 hold for a legacy PHP app **if** every protected
  effect it needs is moved behind typed broker operations [H]. A legacy app that keeps its own DB
  connection keeps its authority: isolating it while leaving the DB reachable contains nothing.
- "Zero code change" Legacy Containment is achievable only for resources the app does not need, such as
  cloud metadata, other services, and internet egress. For the resources it does need, an
  SQL-forwarding proxy would violate SI-16 (no arbitrary SQL). A proxy that only allows a fixed set of
  pre-registered parameterised statements is a possible bridge. It is a broker with a SQL-shaped wire
  format, and it needs its own analysis [H].
- Shared kernel: under runc, one kernel bug breaks all four invariants. gVisor or a microVM is the
  answer when the threat model includes kernel exploits by actor C [F, 16].
- Isolation does nothing against abuse of the broker interface the app legitimately has (confused
  deputy, still-valid grants). Those belong to the authorization layer.

## 5. Q17 — Can we define and test the maximum authority of a compromised process?

**Definition [H]** (object-capability style, after Miller [29]). Authority(W) is the set of
(object, right) pairs that code inside workload W can exercise directly, or transitively through
deputies it can invoke:

```
Authority(W) = Net(W) ∪ FS(W) ∪ IPC(W) ∪ Kern(W) ∪ ⋃_{d ∈ Deputies(W)} Ops_d(W)
```

- **Net:** (address, port, protocol) endpoints routable from W's network namespace, plus anything
  reachable through daemon-side proxies (DNS, port proxy).
- **FS:** paths in W's mount namespace with their effective DAC, MAC, and Landlock rights.
- **IPC:** pathname UNIX sockets W can connect to, abstract sockets in W's network namespace, shared
  IPC/PID namespaces, and inherited file descriptors.
- **Kern:** the syscall surface after seccomp and capabilities. It is the residual channel into the TCB.
- **Ops_d:** for each deputy reachable through IPC/Net (the broker, the nginx gateway), the operations
  it will perform for W. For the broker this is bounded by SI-16 and current grants.

The PBE claim is then: `Authority(W) ∩ ProtectedResources ⊆ Ops_broker(W)`.

**Testability:**
- *Statically*, Net/FS/IPC can be derived from the deployment spec (`docker inspect` output) under a
  model of Docker semantics. This is checkable but only as good as the model; CVE-2024-29018 is an
  example of a gap in such a model [F, 2].
- *Dynamically*, probes (§7) sample the space. They can **falsify** a claim but not prove it.
- *Kern* cannot be bounded formally on Linux without trusting the kernel. That is an explicit
  assumption, not a tested property.
- Formal proof is therefore possible only *relative to* a stated model of kernel and runtime
  semantics. The honest artefact is: an enumerated static authority manifest, a probe suite with
  positive controls, and a listed set of assumptions.

## 6. Deployment Profile P0 (PoC)

### 6.1 Assumptions (all must hold for any claim)

1. A single Linux host or VM. The kernel, dockerd/containerd/runc, the broker image, and the DB are
   uncompromised (I and J out of scope).
2. The operator deploys exactly the Compose file below, and `verify` reports no FAIL.
3. Images are pinned by digest. The application image may contain attacker-controlled code (H in scope).
4. No other workload on the host shares networks or volumes with the broker or the DB.
5. No host service listens on a Docker bridge address in a way that is relevant to the broker's
   network. This matters only for the broker; the workload has no bridge.

### 6.2 Topology

```
client → [web: nginx] ──FastCGI over UDS (volume fcgi)──→ [app: php-fpm, network none]
                                                             │ UDS (volume pbe-app1, ro in app)
                                                             ▼
                                             [broker] ──net "data" (internal)──→ [db: postgres]
```

### 6.3 Compose settings (sketch, not yet tested)

```yaml
x-hardening: &hardening
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]   # default seccomp + AppArmor apply; never "unconfined"
  ipc: private
  pids_limit: 256
  privileged: false

services:
  app:                       # UNTRUSTED workload
    <<: *hardening
    image: pbe/app@sha256:<digest>
    user: "10001:10001"
    network_mode: "none"     # loopback only: no route, no DNS, no metadata, no gateway
    tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
    volumes:
      - fcgi:/run/fcgi            # php-fpm listens here (rw: it must bind)
      - pbe-app1:/run/pbe:ro      # broker socket for THIS workload only; ro prevents unlink/replace
    environment: {}               # no secrets, no DB URL
    mem_limit: 512m
    cpus: 1.0

  web:                       # ingress gateway (trusted config, untrusted traffic)
    <<: *hardening
    image: nginx-unprivileged@sha256:<digest>
    networks: [edge]
    ports: ["127.0.0.1:8080:8080"]
    tmpfs: ["/tmp:rw,nosuid,nodev,size=16m"]
    volumes: [fcgi:/run/fcgi]
    # nginx.conf: fastcgi_pass unix:/run/fcgi/php.sock; fastcgi_ignore_headers X-Accel-Redirect;
    # no proxy_pass locations (prevents app-driven internal redirects to other upstreams)

  broker:                    # TRUSTED
    <<: *hardening
    image: pbe/broker@sha256:<digest>
    user: "10002:10002"
    networks: [data]
    volumes: [pbe-app1:/run/pbe]      # creates /run/pbe/broker.sock; checks SO_PEERCRED uid == 10001
    secrets: [db_broker_password]     # mounted only here
    # policy/keys baked into image or mounted from a volume never attached to app

  db:                        # PROTECTED RESOURCE
    image: postgres@sha256:<digest>
    networks: [data]
    # no ports:; pg_hba.conf: only role pbe_broker, scram-sha-256, from the data subnet; reject all else
    secrets: [db_broker_password]

networks:
  edge: {}                    # needed for published ingress port
  data: { internal: true, driver_opts: { com.docker.network.bridge.enable_icc: "true" } }

volumes: { fcgi: {}, pbe-app1: {} }
secrets: { db_broker_password: { file: ./secrets/db_broker_password } }   # outside app build context
```

Design notes:
- Named volumes, not host bind mounts, to avoid host-path and ownership surprises, especially through
  Colima's macOS file sharing [H].
- One volume and socket per workload (`pbe-appN`) gives the broker workload identity by construction.
  `SO_PEERCRED` adds a UID check [H].
- Connecting to a socket on a read-only mount should still succeed, because the read-only check
  applies to regular files, directories, and symlinks, not socket inodes [V: B-03].
- The app is in its own PID, IPC, network, and mount namespaces. It cannot `ptrace` or signal the
  broker, and cannot see its files.
- Optional P1: add `runtime: runsc` to `app` (gVisor), plus Landlock applied by a launcher, and
  rootless Docker or Podman on production hosts.

### 6.4 Residual risks of P0

1. **Host kernel exploit** from the app (runc shares the kernel). Mitigated by seccomp and dropped
   capabilities, not eliminated. P1 (gVisor) or a microVM addresses this.
2. **Daemon runs as root** (Colima default). A runtime or containerd escape becomes VM-root. Rootless
   mode reduces this [F, 10].
3. **Deputy abuse:** nginx (FastCGI response headers) and the broker interface itself. Out of scope
   for isolation; covered by SI-16 and its tests.
4. **Misconfiguration drift:** one added `networks:`, `volumes:`, `privileged`, or
   `/var/run/docker.sock` mount breaks the profile. `verify` must check configuration (C-xx) as well
   as behaviour.
5. **Side channels and DoS:** timing, cache, and resource exhaustion against co-tenants. Partially
   bounded by cgroups. Not claimed.
6. **In-workload data:** the app still sees all request data and its own memory, and can lie to
   users. Not claimed (see "What these invariants do not promise").
7. **Broker-side reachability:** the broker can reach the DB and anything on `data`. The broker must
   not have internet egress or metadata access (assumption 5).

## 7. Q19 — Operator self-verification: containment probes

Result semantics for `verify`:

- **PASS:** the probe ran inside the real workload context, the boundary held, **and** its positive
  control succeeded (the same action from the broker, or against a known-open target, works). Without
  a positive control, a "blocked" result could be "target down".
- **FAIL:** the forbidden action succeeded, or a configuration check found a forbidden setting.
- **NOT TESTED:** the probe was not run (skipped, disabled, unsupported tooling). It never counts toward a claim.
- **NOT APPLICABLE:** the target provably does not exist in this profile, with evidence (for example,
  the probe confirmed no cloud metadata service). It must not be inferred from assumptions.
- **INCONCLUSIVE:** the probe ran but could not tell the outcomes apart, for example a timeout with a
  failed positive control, missing kernel feature data, or a probe that ran in a context not identical
  to the workload.

Probes run via `docker exec` into the actual `app` container, which inherits its namespaces, seccomp,
capabilities, and user [V: C-08]. Configuration probes run on the host against `docker inspect`.

| ID | Probe | Expected (P0) | Invariant |
|---|---|---|---|
| N-01 | List interfaces (`/sys/class/net`) | only `lo` | SI-01 |
| N-02 | TCP connect to DB by service name and by IP (from inspect) | fail; positive control from broker succeeds | SI-01 |
| N-03 | DNS lookups (internal name, external name, unique canary subdomain to an operator-controlled resolver) | no resolution, no canary hit | SI-01 |
| N-04 | Connect to `169.254.169.254:80`, `[fd00:ec2::254]`, `metadata.google.internal` | fail; NOT APPLICABLE only if the host is proven non-cloud | SI-01/02 |
| N-05 | Connect to bridge gateway, `host.docker.internal`, Colima host address | fail | SI-01 |
| N-06 | Internet egress (TCP 443, UDP 53/443, ICMP) | fail | SI-01 |
| N-07 | Create raw/packet socket | `EPERM` | SI-01 |
| N-08 | Enumerate `/proc/net/unix` and abstract sockets; connect to each | only own sockets | SI-01 |
| F-01 | Plant a unique canary DB password; search env, `/proc/*/environ`, the filesystem, and PHP process memory for it | absent | SI-02 |
| F-02 | Find all socket inodes across mounts; check for `docker.sock`, `containerd.sock`, Docker TCP ports | only `php.sock`, `broker.sock` | SI-01/13 |
| F-03 | Write rootfs; unlink/replace `/run/pbe/broker.sock` | `EROFS` | SI-13 |
| F-04 | Search for broker policy, keys, and config paths | absent | SI-13 |
| P-01 | `/proc/self/status`: `CapEff=0`, `NoNewPrivs:1`, `Seccomp:2`, UID ≠ 0 | as stated | — |
| P-02 | List PIDs; `kill -0`/`ptrace` on any non-own process | none visible | SI-13 |
| P-03 | Attempt `unshare -U`, `mount`, `bpf`, `io_uring_setup`, `keyctl` | denied | — |
| B-01 | Unknown or malformed broker operation | denied | SI-08/16 |
| B-02 | app1 attempts to reach app2's socket (2-workload variant) | not present | SI-06 |
| B-03 | Connect to broker socket on the ro mount | succeeds (positive control) | — |
| D-01 | From a disposable probe container on `data` (not the app): DB login without, or with wrong, credentials | rejected | SI-03 |
| C-01..07 | Inspect `app`: `NetworkMode=none`, `Privileged=false`, `CapAdd` empty, no `seccomp=unconfined`/`apparmor=unconfined`, `ReadonlyRootfs=true`, mount allowlist exact, `PidMode`/`IpcMode` not `host` | as stated | all |
| C-08 | Exec context equals container context (compare `/proc/1/status` and `/proc/self/status` caps, seccomp, uid) | equal, else downstream results INCONCLUSIVE | — |
| K-01 | Kernel version, Landlock ABI (`landlock_create_ruleset` version query) | recorded | info |
| K-02 | Active LSMs (`/sys/kernel/security/lsm`), AppArmor profile of the app process (`/proc/1/attr/current`) | recorded; FAIL if `unconfined` | — |
| K-03 | Docker version ≥ fixed versions for known isolation CVEs (e.g. CVE-2024-29018) | PASS / FAIL | SI-01 |

## 8. Q14 — Smallest genuinely secure deployable configuration

Under the threat model in §1 (actors C, D, H; kernel, runtime, broker, and DB trusted), **P0 is the
proposed minimum**: four containers on one host. The workload has no network namespace connectivity,
a single per-workload UDS to the broker, broker-only DB credentials, and DB-side authentication
restricted to the broker role. Every element maps to a probe. Removing any of them leaves a
falsifiable gap:
- dropping `network_mode: none` → N-0x
- shared credentials → F-01
- DB without auth → D-01
- writable socket mount → F-03

[H, NOT TESTED]. "Genuinely secure" means exactly this: SI-01/02/03/13 under the stated assumptions,
with every probe in §7 PASS. If the threat model is widened to include kernel exploits, the minimum
becomes P1 (gVisor).

## 9. Colima (macOS arm64) vs production Linux

| Aspect | Colima dev | Production Linux | Consequence |
|---|---|---|---|
| Kernel | VM guest kernel (version depends on Colima image) | Host distro kernel | Record with K-01. Landlock ABI and seccomp behaviour can differ [V]. |
| LSM | Depends on the VM image (Ubuntu-based images typically AppArmor) [H] | AppArmor or SELinux | K-02 must report what is actually active. |
| Daemon | Rootful dockerd inside the VM (default) [H] | Rootful, rootless, or Podman | Rootless claims cannot be tested on the default Colima setup. |
| Metadata service | None | Present on cloud VMs | N-04 is NOT APPLICABLE in dev, so **a dev PASS says nothing about cloud IMDS exposure**. |
| Host reachability | Colima forwards published ports to macOS `localhost`; macOS host services may be reachable from the VM [H] | Host services on bridge/`0.0.0.0` | N-05 must include the Colima host address. |
| File sharing | macOS directories mounted into the VM (virtiofs/sshfs) with different ownership semantics [H] | Native | Use named volumes only (P0 does). |
| Nested virtualisation | Needed for Kata/Firecracker/gVisor-KVM. Availability depends on Apple chip generation and macOS version [F\*] | Bare metal or cloud nested virtualisation | Use gVisor systrap in dev. MicroVM profiles are NOT TESTED locally. |
| Architecture | arm64 images | Often amd64 | seccomp profiles are arch-aware. Re-run probes per architecture. |
| Colima/Lima control sockets | On macOS, outside the VM | n/a | Not reachable from containers [H]; F-02 checks the in-VM equivalents. |

## 10. Kubernetes (later)

The equivalent of P0 is:

- a default-deny egress NetworkPolicy for the workload namespace, plus an ingress policy on the DB
  that admits only broker pods;
- `automountServiceAccountToken: false`;
- `hostUsers: false`;
- `securityContext` with `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, and `seccompProfile: RuntimeDefault`;
- optionally `runtimeClassName: gvisor`.

NetworkPolicy "will have no effect" without a plugin that enforces it, and policies are additive
allow-lists [F, 12]. A broker reached by UDS needs both in the same pod, and a shared volume between
containers in a pod is weaker separation than separate pods [H]. Cross-pod brokers need
mTLS or SPIFFE. Default deny also blocks DNS unless it is explicitly allowed. For the workload, it
should stay blocked.

## References

1. Docker CLI reference, `docker network create` (internal mode). https://docs.docker.com/reference/cli/docker/network/create/
2. Moby security advisory CVE-2024-29018 / GHSA-mq39-4gv4-mvpx; Docker Engine 26.0 and 26.1 release notes. https://docs.docker.com/engine/release-notes/26.0/ , https://docs.docker.com/engine/release-notes/26.1/
3. Docker docs, Bridge network driver. https://docs.docker.com/engine/network/drivers/bridge/
4. Docker docs, None network driver. https://docs.docker.com/engine/network/drivers/none/
5. Docker docs, Packet filtering and firewalls. https://docs.docker.com/engine/network/packet-filtering-firewalls/
6. Docker docs, Docker Engine security. https://docs.docker.com/engine/security/
7. Linux kernel docs, No New Privileges flag. https://docs.kernel.org/userspace-api/no_new_privs.html
8. Docker docs, Seccomp security profiles. https://docs.docker.com/engine/security/seccomp/
9. `seccomp_unotify(2)`. https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html
10. Docker docs, Rootless mode. https://docs.docker.com/engine/security/rootless/
11. Podman documentation and Podman 5.0 release notes (pasta default). https://docs.podman.io/
12. Kubernetes docs, Network Policies; User Namespaces. https://kubernetes.io/docs/concepts/services-networking/network-policies/ , https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/
13. Docker docs, AppArmor security profiles. https://docs.docker.com/engine/security/apparmor/
14. Red Hat / container-selinux documentation. https://github.com/containers/container-selinux
15. Linux kernel docs, Landlock: unprivileged access control. https://docs.kernel.org/userspace-api/landlock.html
16. gVisor, Security model. https://gvisor.dev/docs/architecture_guide/security/
17. gVisor, Compatibility. https://gvisor.dev/docs/user_guide/compatibility/
18. gVisor, Platforms and Performance guides. https://gvisor.dev/docs/architecture_guide/platforms/ , https://gvisor.dev/docs/architecture_guide/performance/
19. Firecracker design document. https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md
20. Kata Containers architecture. https://github.com/kata-containers/kata-containers/tree/main/docs/design/architecture
21. AWS EC2 User Guide, Modify instance metadata options. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html
22. AWS EC2 User Guide, IMDS and containers (hop limit). https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
23. `unix(7)`; `user_namespaces(7)`. https://man7.org/linux/man-pages/man7/unix.7.html
24. Docker docs, Protect the Docker daemon socket. https://docs.docker.com/engine/security/protect-access/
25. wasi.dev, Language support. https://wasi.dev/languages
26. VMware Wasm Labs, PHP wasm32-wasi port; PHP dev server on Wasm. https://wasmlabs.dev/articles/php-wasm32-wasi-port , https://wasmlabs.dev/articles/php-dev-server-on-wasm/
27. WordPress Playground, php-wasm in Node.js; team meeting summary (Jan 2026). https://developer.wordpress.org/playground/developers/local-development/php-wasm-node , https://make.wordpress.org/playground/2026/01/
28. Wasmtime security advisories (GitHub). https://github.com/bytecodealliance/wasmtime/security/advisories
29. M. S. Miller, *Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control*, PhD thesis, Johns Hopkins University, 2006.
