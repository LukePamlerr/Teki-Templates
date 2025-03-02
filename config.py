# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///templates.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
