from fastapi import FastAPI, HTTPException, Depends, status, Header
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Annotated, Optional
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import auth
from auth import get_current_user

app = FastAPI()
app.include_router(auth.router)

models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

class PostBase(BaseModel):
    title: str
    content: str
    user_id: int

class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    fullname: Optional[str] = None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    fullname: Optional[str] = None

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return user_dict
    
# def fake_decode_token(token):
#     user = get_user(fake_users_db, token)
#     return user

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     user = fake_decode_token(token)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid authentication credentials",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
#     return user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(user, username: str, password: str):
    if not username == user["email"]:
        return False
    hashed_password = get_password_hash(user["password"])
    if not verify_password(password, hashed_password):
        return False
    return user

# @app.post("/token")
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     username = form_data.username
#     if not username == user["username"]:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#     password = form_data.password
#     if not password == user["password"]:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")

#     return {"access_token": user["username"], "token_type": "bearer"}

# API for authenticate
# @app.post("/login")
# async def login(form_data: OAuth2PasswordRequestForm = Depends()):
#     user_dict = fake_users_db.get(form_data.username)
#     if not user_dict:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")
#     password = form_data.password
#     if not form_data.password == user_dict["password"]:
#         raise HTTPException(status_code=400, detail="Incorrect username or password")

#     return {"access_token": user_dict["username"], "token_type": "bearer"}

# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_user)):
#     return current_user

@app.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    return {"User": user}

# API for user
@app.post("/users/", status_code=status.HTTP_201_CREATED)
async def add_user(user: user_dependency, db: db_dependency, form_data : User): 
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    db_user = models.User(**form_data.dict())
    db.add(db_user)
    db.commit()

@app.get("/users/{user_id}", status_code=status.HTTP_200_OK)
async def read_user(user_id: int, db: db_dependency):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail='User not found')
    return user

@app.delete("/users/{user_id}", status_code=status.HTTP_202_ACCEPTED)
async def delete_user(user_id: int, db: db_dependency):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail='User not found')
    db.delete(user)
    db.commit()

# API for post
@app.post("/posts/", status_code=status.HTTP_201_CREATED)
async def create_post(post: PostBase, db: db_dependency):
    db_post = models.Post(**post.dict())
    db.add(db_post)
    db.commit()

@app.get("/posts/{post_id}", status_code=status.HTTP_200_OK)
async def read_post(post_id: int, db: db_dependency):
    db_post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if db_post is None:
        raise HTTPException(status_code=404, detail="Post was not found")
    return db_post

@app.put("/posts/{post_id}", status_code=status.HTTP_200_OK)
async def update_post(post_id: int, title: str, content: str, db: db_dependency):
    db_post = db.query(models.Post).filter(models.Post.id== post_id).first()
    if db_post is None:
        raise HTTPException(status_code=404, detail="Post was not found")
    db_post.title = title
    db_post.content = content
    db.commit()
    return db_post

@app.delete("/posts/{post_id}", status_code=status.HTTP_200_OK)
async def delete_post(post_id: int, db: db_dependency):
    db_post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if db_post is None:
        raise HTTPException(status_code=404, detail="Post was not found")
    db.delete(db_post)
    db.commit()