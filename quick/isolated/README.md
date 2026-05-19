# quick/isolated

Two-container demo (server + client + nginx backend) that proves the
passage tunnel end-to-end while keeping everything inside a docker
bridge network with **no outbound internet** for the client.

## Topology

```
end user (host)
   │
   ▼  :8080 (published)
┌──────────────┐ public bridge (internet=on)
│ passage-svr  │
└──────────────┘ internal bridge (internet=off)
        ▲
        │ control connection over TLS+yamux
        ▼
┌──────────────┐
│ passage-cli  │
└──────────────┘
        │ dials web -> passage-backend:80
        ▼
┌──────────────┐
│ nginx-backend│
└──────────────┘
```

The `internal` network is created with `internal: true` so neither
the client nor the backend can reach anything outside Docker.

## Run it

```sh
# 1) one-shot: build the binary, generate TLS cert + hybrid
#    Ed25519/ML-DSA-65 client keys, and patch server.yaml/client.yaml
#    with the right pubkeys and fingerprint.
./bootstrap.sh

# 2) bring up the stack.
docker compose up --build

# 3) from another terminal, hit the tunneled service:
curl -i http://localhost:8080/
# nginx welcome page comes back through the tunnel.
```

## Reset

```sh
docker compose down
rm -rf keys
```
