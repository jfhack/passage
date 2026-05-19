# quick/host-image/server

Server side of a two-machine deployment using the prebuilt
`ghcr.io/jfhack/passage:latest` image and `network_mode: host`.
Copy this directory to the public-facing host.

> **Warning** — host networking bypasses container network
> isolation. The container has the same view of the network as the
> host's processes. Only use this mode when you actually need it.

## Steps

1. Edit [server.yaml](server.yaml) — set the `services:` you want
   to expose (default: SSH on port 3022).
2. Run `./bootstrap.sh`. It generates the TLS keypair, prints the
   server fingerprint to share with the client, and prompts for the
   client id and the client's two public keys (Ed25519 and ML-DSA-65
   for hybrid auth, both produced on the client side).
3. `docker compose up -d` to start the server.

The fingerprint and the client's public keys must be exchanged
out-of-band (signed email, internal ticket, etc.).

## Reset

```sh
docker compose down
rm -rf keys
git checkout server.yaml
```
