# Tijori

Standalone, local-first, secret management system designed for agentic workflows.
NOTE: There is currently a /testingReset endpoint. This will go away soon. If you plan to deploy this, comment it out of app/main.py

## Goals

- This is not the same as HashiCorp Vault. It is simpler and has less ceremony, by design.
- no unlock key stored by the system
- docker/local network/tailnet trust boundary. Nothing works without the passphrase - which is *never* stored, so really, *YOU* are the trust boundary.  
- explicit `locked` / `unlocked` behavior
- secret reads only while unlocked
- secret create / replace / delete always require the passphrase

## Storage

The service stores its encrypted files under a mounted container volume.

Default in-container path:

- `/var/lib/scryer-secrets`

Override with:

- `SCRYER_SECRETS_STORAGE_ROOT`

Within that root:

- one encrypted file per secret:
  - `<uuid>.enc`
- one encrypted sentinel:
  - `.sentinel`
- one config file:
  - `config.json`

## Crypto

- KDF: `Argon2id`
- Encryption: `AES-256-GCM`
- Passphrase is never stored
- Only salt and KDF params are stored

## API Semantics

- `locked`
  - secret reads denied
- `unlocked`
  - secret reads allowed to anything that can hit the API

Rules:

- unlock requires the passphrase
- lock does not require the passphrase
- create requires the passphrase
- replace requires the passphrase
- delete requires the passphrase
- unlock TTL must be finite
- maximum TTL:
  - `99 years, 364 days, 23 hours, 59 minutes, 59 seconds`

Operational meaning:

- if Tijori is `locked`, any runtime secret-resolution path should fail immediately
- if Tijori is `unlocked`, anything that can reach the API can read secrets
- unlock state is intentionally coarse-grained right now; policy is mostly network reachability plus Tijori state

## Sentinel

`.sentinel` is a tiny encrypted blob used only to verify that the supplied passphrase derives the correct key.

On unlock:

1. derive key from passphrase + stored salt
2. try to decrypt `.sentinel`
3. if it works, mark the system unlocked until the chosen expiry

## API

- `GET /healthz`
- `GET /status`
- `POST /init`
- `POST /unlock`
- `POST /lock`
- `POST /testingReset` (testing only, remove before shipping)
- `PUT /config/unlock-ttl`
- `POST /secrets`
- `GET /secrets`
- `GET /secrets/{secret_id}`
- `PUT /secrets/{secret_id}`
- `DELETE /secrets/{secret_id}`

Current UI-facing named-secret endpoints:

- `POST /upsertNamedSecret`
- `POST /deleteNamedSecret`
- `POST /getNamesOfSecretsByType`

Useful operational calls:

- `GET /status`
  - returns whether the service is initialized
  - returns whether Tijori is locked
  - returns the current unlock expiry
- `GET /secrets`
  - returns fully resolved secret values
  - only works while unlocked

## How You Should Run Tijori

- run Tijori in a container
- initialize it by attaching to that container and running the CLI inside the container
- mount a persistent volume into `/var/lib/scryer-secrets`
- keep Tijori on an internal Docker network
- do not expose the Tijori API to anything outside that Docker network
- anything that accesses Tijori should be on the same Docker network as Tijori itself

This point matters:

- do not treat Tijori as a public or host-exposed convenience API
- network placement is currently a major part of the trust boundary
- if something can reach Tijori while it is unlocked, it can read secrets

## How To Use This System

1. Start Tijori in its container with persistent storage mounted.
2. Attach to the running container.
3. Run the CLI inside the container to initialize the store.
4. Unlock the store only for a bounded TTL.
5. Create, replace, and delete secrets using the API or CLI while supplying the passphrase.
6. Lock the store again when active secret reads are no longer needed.

Operational guidance:

- keep unlock windows short
- prefer explicit lock/unlock cycles over long-lived unlocked service state
- treat container/network placement as part of the security model
- back up the persistent encrypted storage, not decrypted material

## Current Limitations

- unlock state is process-local memory
- if the service restarts, it comes back locked
- there is no finer-grained authorization layer yet beyond network access plus locked/unlocked state

## Notes

- PM metadata and identity binding can be layered on later
- Scryer-specific usage notes live in [`Scryer Integration.md`](./Scryer%20Integration.md)
