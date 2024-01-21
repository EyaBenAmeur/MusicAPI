from sqlalchemy import Column, Integer, String, Float, Boolean
from sqlalchemy.orm import relationship
from database import Base

class Song(Base):
    __tablename__ = 'songs'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    singer = Column(String)
    copyright_available = Column(Boolean)
    duration_in_min = Column(Integer)

