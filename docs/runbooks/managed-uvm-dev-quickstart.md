# Managed UVM Dev Quickstart

This is the shortest supported path for a local, UHost-managed UVM session in
`v0.1 beta`.

Use it when you want:

- a generated bootstrap token instead of a pasted secret,
- a disposable same-host control-plane state root,
- one managed `software_dbt` runtime session under [`uhostd`](../../cmd/uhostd),
- a shell-friendly session file with the instance and runtime IDs already wired,
- managed HTTP, TCP, and UDP endpoints without dropping to raw QEMU.

## What This Flow Does

Run:

```bash
bash scripts/run-uhost-managed-uvm.sh
```

The helper will:

1. generate a new bootstrap admin token and master key,
2. write a local all-in-one config under `tmp/uhost-managed-uvm`,
3. start [`uhostd`](../../cmd/uhostd),
4. seed the minimum UVM image, template, instance, and runtime records,
5. start one managed UVM session under [`uhost-uvm-runner`](../../cmd/uhost-uvm-runner),
6. write `session.env` and `session.json` with the endpoint, token, and IDs.

## What You Get

- A live control-plane endpoint, by default `http://127.0.0.1:19081`
- A generated token file instead of a hard-coded bearer token
- A managed instance plus runtime session already registered and started
- A resolved-contract read path that reflects the running managed UVM
- A live managed HTTP URL serving guest files under `/var/www`
- A live managed TCP bind for line-oriented ingress tests
- A live managed UDP bind for datagram ingress tests

Load the generated environment:

```bash
source tmp/uhost-managed-uvm/session.env
```

Then inspect the managed runtime:

```bash
curl -fsS \
  -H "Authorization: Bearer $UHOSTCTL_ADMIN_TOKEN" \
  -H "X-UHost-Admin-Token: $UHOSTCTL_ADMIN_TOKEN" \
  "$UHOST_CONTROL_ENDPOINT/uvm/instances/$UHOST_MANAGED_UVM_INSTANCE_ID/resolved-contract" | jq
```

And hit the managed ingress directly:

```bash
curl -fsS "$UHOST_MANAGED_UVM_INGRESS_HTTP_URL"
python3 -c 'import os, socket; s = socket.create_connection((os.environ["UHOST_MANAGED_UVM_INGRESS_TCP_HOST"], int(os.environ["UHOST_MANAGED_UVM_INGRESS_TCP_PORT"])), timeout=3); s.sendall(b"hello from host\n"); s.shutdown(socket.SHUT_WR); print(s.recv(4096).decode())'
python3 -c 'import os, socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"hello from host\n", (os.environ["UHOST_MANAGED_UVM_INGRESS_UDP_HOST"], int(os.environ["UHOST_MANAGED_UVM_INGRESS_UDP_PORT"]))); print(s.recvfrom(4096)[0].decode())'
```

## Access Model

The current managed `software_dbt` dev path is:

- control-plane managed,
- guest-control aware,
- guest-owned usernet-style NAT,
- outbound web plus generic TCP/UDP egress capable through the managed backend,
- inbound HTTP and managed TCP/UDP capable through managed host relays,
- same-host and file-backed.

It is **not** yet:

- an SSH-exposed guest,
- or a post-start guest exec API on the control plane,
- or raw-socket complete like a mature hypervisor-backed guest.

The launcher prints that explicitly and records it in `session.env`:

- `UHOST_MANAGED_UVM_NETWORK_MODE=guest_owned_usernet_nat`
- `UHOST_MANAGED_UVM_INTERNET_NAT=true`
- `UHOST_MANAGED_UVM_SSH_AVAILABLE=false`
- `UHOST_MANAGED_UVM_GUEST_EXEC_AVAILABLE=false`
- `UHOST_MANAGED_UVM_EGRESS_TRANSPORT=guest_owned_tcp_udp_http_https_nat_v1`
- `UHOST_MANAGED_UVM_INGRESS_TRANSPORT=guest_owned_tcp_udp_http_nat_v1`
- `UHOST_MANAGED_UVM_INGRESS_HTTP_URL=http://127.0.0.1:...`
- `UHOST_MANAGED_UVM_INGRESS_TCP_BIND=127.0.0.1:...`
- `UHOST_MANAGED_UVM_INGRESS_TCP_SERVICE=default`
- `UHOST_MANAGED_UVM_INGRESS_UDP_BIND=127.0.0.1:...`
- `UHOST_MANAGED_UVM_INGRESS_UDP_SERVICE=default`
- `UHOST_MANAGED_UVM_GUEST_WEB_ROOT=/var/www`

## Token Generation

If you need a fresh URL-safe token outside the launcher:

```bash
cargo run -q -p uhostctl -- token generate
cargo run -q -p uhostctl -- token generate --shell --env UHOSTCTL_ADMIN_TOKEN
```

## Notes

- The launcher currently applies a dev compatibility bridge so a local
  `software_dbt` image can be promoted and started against the derived host
  class in the disposable state root.
- The managed backend can now perform outbound HTTP/HTTPS fetches through the
  managed backend, open generic TCP and UDP guest egress sessions, serve
  `/var/www` over a managed HTTP listener, and expose managed TCP plus UDP
  ingress binds backed by guest-defined service files. The current control
  plane still does not expose a route to inject new guest-control commands
  after the runtime is already started.
- The launcher is meant for local beta bring-up, not for release evidence or
  production claims.
