# quick/isolated-image/client

Client side of a two-machine deployment using the prebuilt
`ghcr.io/jfhack/passage:latest` image. Copy this directory to the
private-network host whose services you want to expose.

The compose stack runs the passage client plus a sample nginx
backend on an `internal: true` bridge — proving the backend has no
internet access and is only reachable through the tunnel. Replace
the `backend` service with whatever you actually want to expose, or
delete it and point `client.yaml` at any host:port reachable from
the client container.

## Steps

1. Edit [client.yaml](client.yaml) — set `services:` to map service
   names to local backends. The default forwards `web` to
   `passage-backend:80` (the bundled nginx).
2. Run `./bootstrap.sh`. It generates a hybrid Ed25519 + ML-DSA-65
   keypair, prints both public keys to share with the server admin,
   and prompts for the remote address, server fingerprint, and
   client id.
3. `docker compose up -d` to start the client and the backend.

## Verifying

```sh
docker compose exec passage passage verify -config /etc/passage/client.yaml
```

## Reset

```sh
docker compose down
rm -rf keys
git checkout client.yaml
```
