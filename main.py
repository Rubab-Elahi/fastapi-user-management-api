from fastapi import FastAPI, HTTPException, status, Request
from pydantic import BaseModel, EmailStr
from typing import List

app = FastAPI(title="User Management API")

# Simulated in-memory database
db_users = {}

# Pydantic Schemas
class UserCreate(BaseModel):
    id: str        # User explicitly provides ID (e.g. "usr_123", "alice", or UUID)
    email: EmailStr

class UserUpdate(BaseModel):
    email: EmailStr

class UserResponse(BaseModel):
    id: str
    email: EmailStr


# --- ROUTES ---

# 0. ROOT (GET)
@app.get("/")
def read_root():
    return {
        "message": "Welcome to User Management API",
        "docs": "Go to /docs to view interactive documentation",
        "users_endpoint": "/users"
    }

# REQUEST DETAILS ROUTE (GET)
@app.get("/request-info")
def get_request_info(request: Request):
    """
    Demonstrates reading raw HTTP Request details from the client.
    """
    return {
        "client_ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
        "query_params": dict(request.query_params)
    }

# 1. CREATE (POST)
@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate):
    # Check if user ID already exists
    if user.id in db_users:
        raise HTTPException(
            status_code=400, 
            detail=f"User with ID '{user.id}' already exists"
        )
    
    new_user = {"id": user.id, "email": user.email}
    db_users[user.id] = new_user
    return new_user


# 2. READ ALL (GET)
@app.get("/users", response_model=List[UserResponse])
def get_all_users():
    return list(db_users.values())


# 3. READ ONE BY ID (GET)
@app.get("/users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: str):
    if user_id not in db_users:
        raise HTTPException(status_code=404, detail="User not found")
    return db_users[user_id]


# 4. UPDATE (PUT)
@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: str, user: UserUpdate):
    if user_id not in db_users:
        raise HTTPException(status_code=404, detail="User not found")
    
    db_users[user_id]["email"] = user.email
    return db_users[user_id]


# 5. DELETE
@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: str):
    if user_id not in db_users:
        raise HTTPException(status_code=404, detail="User not found")
    
    del db_users[user_id]
    return None