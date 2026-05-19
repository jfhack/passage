# quick/isolated-image/server

Server side of a two-machine deployment using the prebuilt
`ghcr.io/jfhack/passage:latest` image. Runs on a dedicated bridge
network and publishes only the ports it needs (control + tunneled
service). Copy this directory to the public-facing host.

## Steps

1. Edit [server.yaml](server.yaml) and the `ports:` section of
   [docker-compose.yml](docker-compose.yml) — pick the ports you
   want to expose for tunneled services (default: control on
   `:5679`, a `web` service on `:8080`).
2. Run `./bootstrap.sh`. It generates the TLS keypair, prints the
   server fingerprint to share with the client, and prompts for the
   client id plus the client's two public keys (Ed25519 and ML-DSA-65
   for hybrid auth).
3. `docker compose up -d` to start the server.

## Reset

```sh
docker compose down
rm -rf keys
git checkout server.yaml
```
