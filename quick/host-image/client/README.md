# quick/host-image/client

Client side of a two-machine deployment using the prebuilt
`ghcr.io/jfhack/passage:latest` image and `network_mode: host`. Copy
this directory to the private-network host whose services you want
to expose.

## Steps

1. Edit [client.yaml](client.yaml) — set `services:` to map service
   names to local backends (default: forwards `ssh` to
   `127.0.0.1:22`).
2. Run `./bootstrap.sh`. It generates a hybrid Ed25519 + ML-DSA-65
   keypair, prints both public keys to share with the server admin,
   and prompts for the remote address, server fingerprint, and
   client id.
3. `docker compose up -d` to start the client.

The public keys and the server fingerprint must be exchanged
out-of-band.

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
