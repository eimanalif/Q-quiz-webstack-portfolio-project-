import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard_to_guess_string'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///q_quiz.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

