from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

app = FastAPI()
BASE_TABLE = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81]

# Your exact encryption algorithm from your original code
def encrypt_algo_4(plain_bytes):
    out = []
    for i, b in enumerate(plain_bytes):
        xor_byte = b ^ BASE_TABLE[i % len(BASE_TABLE)]
        rotated = ((xor_byte << 2) & 0xFF) | (xor_byte >> 6)
        out.append(rotated & 0xFF)
    return bytes(out)

# Define the input structure expected from the C++ library or manager
class PayloadRequest(BaseModel):
    algo_index: int
    plain_text: str

@app.post("/get_payload")
def get_payload(request: PayloadRequest):
    if request.algo_index != 4:
        raise HTTPException(status_code=400, detail="Only algo_index 4 is currently configured.")

    raw_bytes = request.plain_text.encode('utf-8')
    ciphertext_bytes = encrypt_algo_4(raw_bytes)

    # Match your exact format: "algo|hex_string"
    final_payload_string = f"{request.algo_index}|{ciphertext_bytes.hex()}"

    return {"payload": final_payload_string}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
