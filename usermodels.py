from sqlalchemy import Column, Integer, String
from userbase import uBase

class User(uBase):
    __tablename__ = 'users'  # Specify the table name

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    password = Column(String)
