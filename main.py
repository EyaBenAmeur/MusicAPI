
from fastapi import FastAPI, HTTPException, Depends,status, APIRouter, Query
from typing import Annotated, List
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import delete
from pydantic import BaseModel
from database import SessionLocal, engine
from userbase import SessionLocal_user,uengine
from fastapi.middleware.cors import CORSMiddleware
import models as models
import usermodels as usermodels
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from usermodels import User
from models import Song
from typing import List
from sqlalchemy import or_
from fastapi import Form
from fastapi import Depends
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = "6be65514e0ddd84f7e110c292d71d962"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
# Create tables for models
models.Base.metadata.create_all(bind=engine)

# Create tables for usermodels
usermodels.uBase.metadata.create_all(bind=uengine)
app = FastAPI()

origins = [
    "http://localhost:8000",  # Replace with the actual origin of your frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Defining Models for Data in/out API
class SongBase(BaseModel):
    name: str
    singer: str
    copyright_available: bool
    duration_in_min: int

class SongModel(SongBase):
    id: int

    class Config:
        from_attributes = True
     

# Database Connection Setup
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

#models.Base.metadata.create_all(bind=engine)

class UserBase(BaseModel):
    username: str
    password: str


class UserModel(UserBase):
    user_id: int

    class Config:
        from_attributes = True
     

# Database Connection Setup
def get_userdb():
    userdb = SessionLocal_user()
    try:
        yield userdb
    finally:
        userdb.close()

userdb_dependency = Annotated[Session, Depends(get_userdb)]

#usermodels.uBase.metadata.create_all(bind=uengine)

def get_user_details_from_database(userdb: Session, username: str):
    db_user = userdb.query(usermodels.User).filter_by(username=username).first()
    if db_user:
        return {'id': db_user.user_id, 'username': db_user.username, 'password': db_user.password}
    else:
        return None


# Add a new dependency for token-based authentication
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    return {"username": username}

def authenticate_user(username: str, password: str, userdb: Session):
    # This is a simple example. In a real application, you would likely query your database.
    db_user = userdb.query(User).filter_by(username=username, password=password).first()
    return db_user

# Define the /token endpoint for OAuth2 password flow
@app.post("/token")
async def generate_token(username: str = Form(...), password: str = Form(...), userdb: Session = Depends(get_userdb)):
    user = authenticate_user(username, password, userdb)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = {"sub": username}
    access_token = create_access_token(token_data)
    return {"access_token": access_token, "token_type": "bearer"}




@app.get("/")
async def welcome():
    return {"message": "Welcome to the Content Creators Music Guidance. Check SWAGGER at http://localhost:8000/docs"} 
  

# Register a new user
@app.post("/SignIn/", response_model=UserModel)
async def CreateAnAccount(user: UserBase, userdb: userdb_dependency):
    # Check if the password already exists
    existing_username_user = userdb.query(usermodels.User).filter_by(username=user.username).first()
    if existing_username_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="INVALID USERNAME please try another username")

    # If the password doesn't exist, proceed with registration
    db_user = usermodels.User(**user.dict())
    userdb.add(db_user)
    userdb.commit()
    userdb.refresh(db_user)
    return db_user
global user_details
user_details = {
    'id': 0,
    'username': 'default',
    'password': 'default'}

@app.post("/login/", response_model=dict)
async def AccessAccount(user: UserBase, userdb: userdb_dependency):
    db_user = userdb.query(usermodels.User).filter_by(username=user.username, password=user.password).first()
    if db_user:
        global user_details
        user_details = get_user_details_from_database(userdb, username=user.username)

        # Create a token for the user
        token_data = {"sub": user_details["username"]}
        access_token = create_access_token(token_data)

        # Return the token in the response body
        return {"message": "Successfully logged in", "token": access_token}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password, Try again")

#LOGOUT
# User logout 
@app.get("/logout")
def logout():
    global user_details

    # Update user details on logout
    user_details = {
        'id': 0,
        'username': 'default',
        'password': 'default'
    }

    # Return a message
    return {"message": "Successfully logged out"}
# Secure the /Songs/ endpoint for adding new songs with the get_current_user dependency
@app.post("/Songs/", response_model=SongModel)
async def add_new_song(song: SongBase, db: db_dependency, current_user: dict = Depends(get_current_user)):
    # Check if the user has the required permissions
    if current_user['username'] != 'EYABENAMEUR':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Add the new song to the database
    db_song = models.Song(**song.model_dump())
    db.add(db_song)
    db.commit()
    db.refresh(db_song)

    return db_song

#endpoint for getting all songs
@app.get("/Songs/", response_model=List[SongModel])
async def get_all_songs(db: db_dependency):
    # Retrieve all songs from the database
    songs = db.query(models.Song).all()
    return songs

# Delete a song (accessible only by admin)
@app.delete("/Songs/{song_id}", response_model=SongModel)
async def DeleteSong(song_id: int, db: db_dependency):
    # Check if the user has the required permissions
    if user_details.get('id') == 0 or user_details.get('username') != 'EYABENAMEUR':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Check if the song exists
    db_song = db.query(models.Song).filter_by(id=song_id).first()
    if not db_song:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Song not found")

    # Delete the song from the database
    db.execute(delete(models.Song).where(models.Song.id == song_id))
    db.commit()

    return db_song


#get list of users (admin only)
@app.get("/users/", response_model=List[UserModel])
async def get_all_users(userdb: userdb_dependency):
    # Check if the user has admin permissions
    if user_details.get('id') == 0 or user_details.get('username') != 'EYABENAMEUR':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Retrieve all users from the database
    users = userdb.query(usermodels.User).all()
    return users    
#delete user (only admin)
@app.delete("/users/{user_id}", response_model=UserModel)
async def delete_user(user_id: int, userdb: userdb_dependency):
    # Check if the user has admin permissions
    if user_details.get('id') == 0 or user_details.get('username') != 'EYABENAMEUR':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Check if the user to be deleted exists
    db_user = userdb.query(usermodels.User).filter_by(user_id=user_id).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Delete the user from the database
    userdb.delete(db_user)
    userdb.commit()
    return db_user
# Get song by ID
@app.get("/songs/{song_id}", response_model=SongModel)
async def get_song_by_id(song_id: int, db: db_dependency):
    song = db.query(models.Song).filter_by(id=song_id).first()
    if not song:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Song not found")
    return song

# Get song by name
@app.get("/songs/by_name/", response_model=List[SongModel])
async def get_song_by_name(name: str, db: db_dependency):
    songs = db.query(models.Song).filter(models.Song.name.ilike(f"%{name}%")).all()
    return songs

# Get song by singer
@app.get("/songs/by_singer/", response_model=List[SongModel])
async def get_song_by_singer(singer: str, db: db_dependency):
    songs = db.query(models.Song).filter(models.Song.singer.ilike(f"%{singer}%")).all()
    return songs

# Get songs by a specific duration
@app.get("/songs/by_duration/", response_model=List[SongModel])
async def get_songs_by_duration(duration: int, db: db_dependency):
    songs = db.query(models.Song).filter(models.Song.duration_in_min == duration).all()
    return songs


# Get songs by copyright availability
@app.get("/songs/by_copyright/", response_model=List[SongModel])
async def get_songs_by_copyright(copyright_available: bool, db: db_dependency):
    songs = db.query(models.Song).filter_by(copyright_available=copyright_available).all()
    return songs

# Update user password
@app.put("/update_password/")
async def update_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    userdb: Session = Depends(get_userdb)
):
    # Check if the user is logged in
    if user_details.get('id') == 0:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not logged in")

    # Check if the current password matches the user's stored password
    db_user = userdb.query(usermodels.User).filter_by(user_id=user_details['id']).first()
    if not db_user or db_user.password != current_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect current password")

    # Update the user's password
    db_user.password = new_password
    userdb.commit()

    return {"message": "Password updated successfully"}

  # Update song copyright availability (accessible only by admin)
@app.put("/songs/update_copyright/{song_id}", response_model=SongModel)
async def update_copyright(
    song_id: int,
    new_copyright_availability: bool,
    db: db_dependency
):
    # Check if the user has admin permissions
    if user_details.get('id') == 0 or user_details.get('username') != 'EYABENAMEUR':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

    # Check if the song exists
    db_song = db.query(models.Song).filter_by(id=song_id).first()
    if not db_song:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Song not found")

    # Update the song's copyright availability
    db_song.copyright_available = new_copyright_availability
    db.commit()

    return db_song 