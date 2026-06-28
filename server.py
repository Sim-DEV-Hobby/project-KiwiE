from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

app = FastAPI()
BASE_TABLE = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81]


# --- THE 5 REVERSE MATCHING ENCRYPTION ROUTINES ---

def encrypt_algo_0(plain_bytes):
    out = []
    for i, b in enumerate(plain_bytes):
        out.append(b ^ BASE_TABLE[i % len(BASE_TABLE)] ^ i)
    return bytes(out)


def encrypt_algo_1(plain_bytes):
    out = []
    state = 0xAA
    for i, b in enumerate(plain_bytes):
        cipher_byte = b ^ BASE_TABLE[i % len(BASE_TABLE)] ^ state
        out.append(cipher_byte)
        state = ((state + cipher_byte) ^ 0x1F) & 0xFF
    return bytes(out)


def encrypt_algo_2(plain_bytes):
    out = []
    for i, b in enumerate(plain_bytes):
        out.append(((b ^ BASE_TABLE[(i + 2) % len(BASE_TABLE)]) + 5) & 0xFF)
    return bytes(out)


def encrypt_algo_3(plain_bytes):
    out = []
    state_a, state_b = 0x55, 0xCC
    working_table = list(BASE_TABLE)
    for i, b in enumerate(plain_bytes):
        cipher_byte = ((b + state_b) & 0xFF) ^ working_table[i % len(working_table)] ^ state_a
        out.append(cipher_byte)
        state_a = ((state_a ^ cipher_byte) + 0x1F) & 0xFF
        state_b = ((state_b + b) ^ 0x7B) & 0xFF
    return bytes(out)


def encrypt_algo_4(plain_bytes):
    out = []
    for i, b in enumerate(plain_bytes):
        xor_byte = b ^ BASE_TABLE[i % len(BASE_TABLE)]
        rotated = ((xor_byte << 2) & 0xFF) | (xor_byte >> 6)
        out.append(rotated & 0xFF)
    return bytes(out)


# --- ROUTER MAP ---
ENCRYPTION_FUNCTIONS = {
    0: encrypt_algo_0,
    1: encrypt_algo_1,
    2: encrypt_algo_2,
    3: encrypt_algo_3,
    4: encrypt_algo_4
}


class PayloadRequest(BaseModel):
    algo_index: int
    plain_text: str


@app.post("/get_payload")
def get_payload(request: PayloadRequest):
    # Dynamically check if the requested algorithm index exists
    if request.algo_index not in ENCRYPTION_FUNCTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid algo_index. Choose a value between 0 and 4."
        )

    raw_bytes = request.plain_text.encode('utf-8')

    # Execute the selected algorithm function dynamically
    encrypt_func = ENCRYPTION_FUNCTIONS[request.algo_index]
    ciphertext_bytes = encrypt_func(raw_bytes)

    # Match exact format: "algo|hex_string"
    final_payload_string = f"{request.algo_index}|{ciphertext_bytes.hex()}"

    return {"payload": final_payload_string}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
