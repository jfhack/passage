# quick/host

Same flow as `quick/isolated/` but both containers run with
`network_mode: host`. The demo exposes the host's SSH (or any local
service) on port 3022 of the host through the passage tunnel.

> **Warning** — host networking bypasses container network isolation.
> The container has the same view of the network as the host's
> processes: any port it binds is bound on the host directly, and any
> outbound connection appears to come from the host. Only use this
> mode when you actually need it (e.g., to forward a host-level
> service like SSH on `127.0.0.1:22`).

## Run it

```sh
./bootstrap.sh
docker compose up --build
ssh -p 3022 user@127.0.0.1   # tunneled to 127.0.0.1:22
```

## Reset

```sh
docker compose down
rm -rf keys
```
