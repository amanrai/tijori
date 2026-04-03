from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from .schemas import (
    InitRequest,
    InitResponse,
    LockResponse,
    NamedSecretDeleteRequest,
    NamesOfSecretsByTypeRequest,
    NamesOfSecretsByTypeResponse,
    NamedSecretUpsertRequest,
    SecretCreateRequest,
    SecretCreateResponse,
    SecretDeleteRequest,
    SecretListResponse,
    SecretResponse,
    SecretUpdateRequest,
    StatusResponse,
    TTLRequest,
    UnlockRequest,
)
from .service import secret_service


app = FastAPI(title="Scryer Secrets", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"ok": "true"}


@app.get("/status", response_model=StatusResponse)
def status() -> StatusResponse:
    return secret_service.status()


@app.post("/init", response_model=InitResponse)
def init(req: InitRequest) -> InitResponse:
    status = secret_service.init(req.passphrase, req.unlock_ttl_seconds)
    return InitResponse(
        initialized=status.initialized,
        locked=status.locked,
        unlocked_until=status.unlocked_until,
    )


@app.post("/unlock", response_model=InitResponse)
def unlock(req: UnlockRequest) -> InitResponse:
    status = secret_service.unlock(req.passphrase, req.unlock_ttl_seconds)
    return InitResponse(
        initialized=status.initialized,
        locked=status.locked,
        unlocked_until=status.unlocked_until,
    )


@app.post("/lock", response_model=LockResponse)
def lock() -> LockResponse:
    status = secret_service.lock()
    return LockResponse(locked=status.locked)


@app.post("/testingReset", response_model=StatusResponse)
def testing_reset() -> StatusResponse:
    # Testing-only endpoint. Remove before shipping.
    return secret_service.testing_reset()


@app.put("/config/unlock-ttl", response_model=StatusResponse)
def update_unlock_ttl(req: TTLRequest) -> StatusResponse:
    return secret_service.update_ttl(req.passphrase, req.unlock_ttl_seconds)


@app.post("/secrets", response_model=SecretCreateResponse, status_code=201)
def create_secret(req: SecretCreateRequest) -> SecretCreateResponse:
    created = secret_service.create_secret(req.name, req.user_defined_type, req.passphrase, req.value)
    return SecretCreateResponse(**created)


@app.post("/upsertNamedSecret", response_model=SecretCreateResponse)
def upsert_named_secret(req: NamedSecretUpsertRequest) -> SecretCreateResponse:
    created = secret_service.upsert_named_secret(req.name, req.user_defined_type, req.passphrase, req.value)
    return SecretCreateResponse(**created)


@app.post("/deleteNamedSecret", status_code=204)
def delete_named_secret(req: NamedSecretDeleteRequest) -> Response:
    secret_service.delete_named_secret(req.name, req.user_defined_type, req.passphrase)
    return Response(status_code=204)


@app.post("/getNamesOfSecretsByType", response_model=NamesOfSecretsByTypeResponse)
def get_names_of_secrets_by_type(req: NamesOfSecretsByTypeRequest) -> NamesOfSecretsByTypeResponse:
    return NamesOfSecretsByTypeResponse(
        names=secret_service.get_names_of_secrets_by_type(req.user_defined_type)
    )


@app.get("/secrets", response_model=SecretListResponse)
def list_secrets() -> SecretListResponse:
    return SecretListResponse(secrets=secret_service.list_secrets())


@app.get("/secrets/{secret_id}", response_model=SecretResponse)
def read_secret(secret_id: str) -> SecretResponse:
    return SecretResponse(**secret_service.read_secret(secret_id))


@app.put("/secrets/{secret_id}", status_code=204)
def replace_secret(secret_id: str, req: SecretUpdateRequest) -> Response:
    secret_service.replace_secret(secret_id, req.passphrase, req.value)
    return Response(status_code=204)


@app.delete("/secrets/{secret_id}", status_code=204)
def delete_secret(secret_id: str, req: SecretDeleteRequest) -> Response:
    secret_service.delete_secret(secret_id, req.passphrase)
    return Response(status_code=204)
