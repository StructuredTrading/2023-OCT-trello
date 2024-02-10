from datetime import timedelta

from flask import Blueprint, request
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import create_access_token
from psycopg2 import errorcodes

from init import db, bcrypt
from models.users import User, user_schema

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route("/register", methods=["POST"]) # /auth/register
def auth_register():
    try:
        # the data that we get in body of the request
        data = request.get_json()
        # password from the request body
        password = data.get('password')
        hashed_password = ""
        # if password exists, hash the password
        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # create the user instance
        user = User(
            name=data.get('name'),
            email=data.get('email'),
            password=hashed_password
        )

        # add and commit the user to DB
        db.session.add(user)
        db.session.commit()
        # Repond back to the client
        return user_schema.dump(user), 201

    except IntegrityError as err:
        print(err.orig.pgcode)
        if err.orig.pgcode == errorcodes.NOT_NULL_VIOLATION:
            return {"error": f"The {err.orig.diag.column_name} is required"}
        if err.orig.pgcode == errorcodes.UNIQUE_VIOLATION:
            return {"error": "Email address already in use"}, 409
    

@auth_bp.route("/login", methods=["POST"]) # /auth/login
def auth_login():
    # get the data from the request body
    data = request.get_json()
    # Find the user with the email address
    stmt = db.select(User).filter_by(email=data.get("email"))
    user = db.session.scalar(stmt)
    # If user exists and password is correct
    if user and bcrypt.check_password_hash(user.password, data.get("password")):
        # create jwt
        token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))
        # return the token along with the user info
        return {"email": user.email, "token": token, "is_admin": user.is_admin}
    # else
    else:
        # return error
        return {"error": "Invalid email or password"}, 401