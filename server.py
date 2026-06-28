import os
import json
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import uvicorn

app = FastAPI()
DATA_FILE = "users.json"

def find_user_in_file(username: str):
    if not os.path.exists(DATA_FILE):
        return None
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            users_list = json.load(f)
            for user in users_list:
                if user.get("username") == username:
                    return user
        except json.JSONDecodeError:
            return None
    return None

# --- THE 5 ENCRYPTION ALGORITHMS ---
BASE_TABLE = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81]

def encrypt_algo_0(b_arr): return bytes([b ^ BASE_TABLE[i % 8] ^ i for i, b in enumerate(b_arr)])
def encrypt_algo_1(b_arr):
    out, state = [], 0xAA
    for i, b in enumerate(b_arr):
        c = b ^ BASE_TABLE[i % 8] ^ state
        out.append(c)
        state = ((state + c) ^ 0x1F) & 0xFF
    return bytes(out)
def encrypt_algo_2(b_arr): return bytes([((b ^ BASE_TABLE[(i + 2) % 8]) + 5) & 0xFF for i, b in enumerate(b_arr)])
def encrypt_algo_3(b_arr):
    out, state_a, state_b = [], 0x55, 0xCC
    for i, b in enumerate(b_arr):
        c = ((b + state_b) & 0xFF) ^ BASE_TABLE[i % 8] ^ state_a
        out.append(c)
        state_a = ((state_a ^ c) + 0x1F) & 0xFF
        state_b = ((state_b + b) ^ 0x7B) & 0xFF
    return bytes(out)
def encrypt_algo_4(b_arr):
    out = []
    for i, b in enumerate(b_arr):
        x = b ^ BASE_TABLE[i % 8]
        out.append((((x << 2) & 0xFF) | (x >> 6)) & 0xFF)
    return bytes(out)

ENCRYPTION_FUNCTIONS = {0: encrypt_algo_0, 1: encrypt_algo_1, 2: encrypt_algo_2, 3: encrypt_algo_3, 4: encrypt_algo_4}

# --- ENDPOINTS ---

class ProfileRequest(BaseModel):
    algo_index: int
    username: str
    hwid: str  # Client must pass their hardware ID

@app.post("/get_payload")
def get_payload(request: ProfileRequest):
    if request.algo_index not in ENCRYPTION_FUNCTIONS:
        raise HTTPException(status_code=400, detail="Invalid algo_index.")

    # 1. Fetch user account data 
    user = find_user_in_file(request.username)
    if not user:
        raise HTTPException(status_code=404, detail="User account profile not found.")

    # 2. Enforce HWID Protection Check
    if user["hwid"] != request.hwid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Hardware ID spoofing or mismatch detected. Access denied."
        )

    # 3. Package data into the "A|B|C|D" pipe format
    raw_profile_string = f"{user['username']}|{user['subscription_plan']}|{user['hwid']}|{user['expires_at']}"
    
    # 4. Encrypt the profile package
    raw_bytes = raw_profile_string.encode('utf-8')
    encrypt_func = ENCRYPTION_FUNCTIONS[request.algo_index]
    ciphertext_bytes = encrypt_func(raw_bytes)

    # 5. Build network data payload output
    final_payload_string = f"{request.algo_index}|{ciphertext_bytes.hex()}"
    return {"payload": final_payload_string}

@app.get("/")
def read_root():
    return {"status": "online", "engine": "FastAPI HWID Secure Routing Engine"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
