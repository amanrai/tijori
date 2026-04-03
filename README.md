# tijori

Standalone local secret system.

This is intentionally separate from PM and intended to run in its own container.

## Runtime Location

Current default access points:

- from the host:
  - `http://127.0.0.1:8211`
- from workflow hooks / other containers:
  - `http://host.docker.internal:8211`

Port:

- `8211`

## Goals

- no Vault
- no secret values stored in PM
- no unlock key stored by the system
- local/tailnet trust boundary
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

## Product Semantics

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

- if the vault is `locked`, any runtime secret-resolution path should fail immediately
- if the vault is `unlocked`, anything that can reach the API can read secrets
- unlock state is intentionally coarse-grained right now; project-level selection controls exposure, but API access still depends on network reachability plus vault state

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
  - returns whether the vault is locked
  - returns the current unlock expiry
- `GET /secrets`
  - returns fully resolved secret values
  - only works while unlocked

## Secret Types In Use

Current Scryer conventions:

- `git_identity`
  - used for named git / forge identities
- `environment_variable`
  - used for named environment-variable values

Current example shapes:

- `git_identity`
  - `{"name":"forgejo","provider":"self-hosted","url":"http://...","username":"...","git_user_name":"...","git_user_email":"...","access_token":"..."}`
- `environment_variable`
  - `{"SAMPLE_ENV_VARIABLE":"sample environment variable value."}`

The `environment_variable` wrapper shape exists so the stored record remains self-describing by variable name.

## Workflow Integration

Workflows do not define secrets themselves.

The model is:

1. identities and variables are defined centrally in this service
2. projects select which names are exposed to runtime
3. orchestrator writes those selected names into `state.json`
4. hook-side helper code resolves the selected names against this service at runtime

Current runtime contract pieces:

- `project_identities_associated`
- `project_environment_variables_associated`
- `secrets_service_url`

Current helper behavior:

- hooks should read `secrets_service_url` from `state.json`
- hooks should check `GET /status` before attempting reads
- if locked, hooks should fail immediately rather than silently continue
- if unlocked, hooks can resolve the selected names via `GET /secrets`

## Current Limitations

- unlock state is process-local memory
- if the service restarts, it comes back locked
- there is no finer-grained authorization layer yet beyond network access plus locked/unlocked state
- hooks currently resolve from `GET /secrets`, which is simple but broad; a narrower lookup path may be desirable later
- project exposure filtering happens in Scryer, not inside the secrets service itself

## Container Notes

Expected container behavior:

- mount a persistent host volume into `/var/lib/scryer-secrets`
- expose port `8211`
- keep this service on the same trusted local/tailnet boundary as the rest of Scryer

## Notes

- unlock state is process-local memory
- if the service restarts, it comes back locked
- PM metadata and identity binding can be layered on later
