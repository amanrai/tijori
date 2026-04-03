# Scryer Integration

This document captures the current Scryer-specific usage of Tijori.

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

1. identities and variables are defined centrally in Tijori
2. projects select which names are exposed to runtime
3. orchestrator writes those selected names into `state.json`
4. hook-side helper code resolves the selected names against Tijori at runtime

Current runtime contract pieces:

- `project_identities_associated`
- `project_environment_variables_associated`
- `secrets_service_url`

Current helper behavior:

- hooks should read `secrets_service_url` from `state.json`
- hooks should check `GET /status` before attempting reads
- if locked, hooks should fail immediately rather than silently continue
- if unlocked, hooks can resolve the selected names via `GET /secrets`

## Current Scryer-Specific Limitations

- hooks currently resolve from `GET /secrets`, which is simple but broad; a narrower lookup path may be desirable later
- project exposure filtering happens in Scryer, not inside Tijori itself
