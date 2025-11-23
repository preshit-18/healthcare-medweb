import flask_cors
from flask import Flask, request, jsonify, g
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from pymongo import errors
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from bson.objectid import ObjectId


load_dotenv()

app = Flask(__name__)
flask_cors.CORS(app)

uri = os.getenv("MONGOURI")

db_client = MongoClient(uri)
db = db_client["doctor-consultancy"]  
users_collection = db["users"]  


MONGOURI = os.getenv("MONGOURI")
JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret_in_production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "60"))
FERNET_KEY = os.getenv("FERNET_KEY")  

# Setup Fernet if key provided
fernet = Fernet(FERNET_KEY.encode()) if FERNET_KEY else None

# Mongo client
if not MONGOURI:
    raise RuntimeError("MONGOURI environment variable is required")

client = MongoClient(MONGOURI)
db = client.get_database()  # default DB from connection string
users_collection = db.get_collection("users")


# ---------- Utility helpers ----------

def hash_password(plain_password: str) -> str:
    return generate_password_hash(plain_password, method="pbkdf2:sha256", salt_length=16)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return check_password_hash(hashed_password, plain_password)


def encrypt_field(value: str) -> str:
    """Encrypt a string value using Fernet. Returns base64 urlsafe string."""
    if not fernet:
        raise RuntimeError("FERNET_KEY not configured")
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_field(token: str) -> str:
    if not fernet:
        raise RuntimeError("FERNET_KEY not configured")
    return fernet.decrypt(token.encode("utf-8")).decode("utf-8")


def generate_token(user_id: str) -> str:
    now = datetime.now()
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXP_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

# ---------- Decorator for protected routes ----------

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            token = token.replace("Bearer ", "")
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_id = data["user_id"]
        except Exception as e:
            return jsonify({"error": "Invalid or expired token"}), 401

        return f(*args, **kwargs)

    return wrapper


# ---------- Routes ----------

@app.post("/register")
def register():
    data = request.json

    required = ["userName", "contactNumber", "email", "age", "gender", "password"]
    if not all(field in data for field in required):
        return jsonify({"error": "Missing fields"}), 400

    # Check if email already exists
    if users_collection.find_one({"email": data["email"]}):
        return jsonify({"error": "Email already registered"}), 409

    hashed_password = hash_password(data["password"])

    user_doc = {
        "userName": data["userName"],
        "contactNumber": data["contactNumber"],
        "email": data["email"],
        "age": data["age"],
        "gender": data["gender"],
        "password": hashed_password,
    }

    result = users_collection.insert_one(user_doc)

    return jsonify({
        "message": "User registered successfully",
        "user_id": str(result.inserted_id)
    }), 201


@app.post("/login")
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = users_collection.find_one({"email": email})

    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    if not verify_password(password, user["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    token = jwt.encode(
        {"user_id": str(user["_id"])},
        JWT_SECRET,
        algorithm="HS256"
    )

    return jsonify({
        "message": "Login successful",
        "token": token
    }), 200


@app.get("/profile")
@token_required
def profile():
    user = users_collection.find_one({"_id": ObjectId(request.user_id)})
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    user["_id"] = str(user["_id"])
    user.pop("password")

    return jsonify(user), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
