
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Demo tạm thời để kiểm tra kết nối.
# Sau này thay bằng domain thật của test2.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "Python API is running"}

@app.get("/api/test")
def test():
    return {
        "success": True,
        "message": "Xin chào từ Python server!",
        "images": [
            {"name": "image_001.jpg", "similarity": 0.98},
            {"name": "image_002.jpg", "similarity": 0.94},
            {"name": "image_003.jpg", "similarity": 0.89}
        ]
    }
