from flask import Blueprint
from init import db, bcrypt
from models.users import User

db_commands = Blueprint('db', __name__)


# Creates the tables in database
@db_commands.cli.command('create')
def create_tables():
    db.create_all()
    print("Tables created.")


# Drops tables from database
@db_commands.cli.command('drop')
def drop_tables():
    db.drop_all()
    print("Tables dropped")


# Populate the tables in database
@db_commands.cli.command('seed')
def seed_tables():
    users = [
        User(
            name="Admin",
            email="admin@email.com",
            password=bcrypt.generate_password_hash('123456').decode('utf-8'),
            is_admin=True
        ),
        User(
            name="User 1",
            email="user1@email.com",
            password=bcrypt.generate_password_hash('123456').decode('utf-8')
        )
    ]

    db.session.add_all(users)
    db.session.commit()
    print("Tables seeded")