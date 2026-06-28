import os
import json
import random  # Added for dynamic algorithm picking
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import uvicorn

app = FastAPI()
DATA_FILE = "users.json"

import requests

BIN_ID = "6a414163f5f4af5e293da1c8"
API_KEY = "$2a$10$fXGoPLJp6ExOMyOpr/xpA.xKugc/zuKkxXQSP48WYQgvpRUD9HE.q"

def find_user_in_file(username: str):
    # This explicit string concatenation prevents any variable bleeding into the host domain name
    base_api_url = "https://jsonbin.io"
    url = base_api_url + str(BIN_ID) + "/latest"
    
    headers = {"X-Master-Key": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_data = response.json()
            
            if "record" in json_data:
                users_list = json_data["record"]
            else:
                users_list = json_data
                
            for user in users_list:
                if user.get("username") == username:
                    return user
        else:
            print("❌ JSONbin Error Status Code: " + str(response.status_code))
    except Exception as e:
        print("Cloud Read Error: " + str(e))
    return None


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

# FIXED: Removed algo_index from the incoming payload contract
class ProfileRequest(BaseModel):
    username: str
    hwid: str  

@app.post("/get_payload")
def get_payload(request: ProfileRequest):
    user = find_user_in_file(request.username)
    if not user:
        raise HTTPException(status_code=404, detail="User account profile not found.")

    if user["hwid"] != request.hwid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Hardware ID spoofing or mismatch detected. Access denied."
        )

    # 1. Randomly pick an algorithm matrix index (0 to 4)
    selected_algo = random.choice(list(ENCRYPTION_FUNCTIONS.keys()))

    # 2. Package data and run encryption
    raw_profile_string = f"{user['username']}|{user['subscription_plan']}|{user['hwid']}|{user['expires_at']}"
    raw_bytes = raw_profile_string.encode('utf-8')
    
    encrypt_func = ENCRYPTION_FUNCTIONS[selected_algo]
    ciphertext_bytes = encrypt_func(raw_bytes)

    # 3. Output payload string starts with the designated algorithm type character
    final_payload_string = f"{selected_algo}|{ciphertext_bytes.hex()}"
    return {"payload": final_payload_string}

@app.get("/")
def read_root():
    return {"status": "online"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

