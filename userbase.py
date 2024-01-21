from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

URL_DATABASE = 'sqlite:///./users.db'

uengine = create_engine(URL_DATABASE, connect_args={"check_same_thread": False})

SessionLocal_user = sessionmaker(autocommit=False, autoflush=False, bind=uengine)

uBase = declarative_base()