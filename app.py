from flask import Flask, request
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import datetime
import bcrypt
import os
from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

app = Flask(__name__) 
app.config["JWT_SECRET_KEY"] = "044a7dcd3dff50c8130da541243d7db7"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=5)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(hours=1)



basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
 

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        """Hashes the password using bcrypt and stores it in the password_hash field."""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        """Checks the password against the stored bcrypt hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def toJSON(self):
        """Returns a JSON-serializable representation of the User."""
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email
        }
    

jwt = JWTManager(app)

@app.route("/")
@jwt_required()
def index():

    authuser = db.query(User).filter_by(id=get_jwt_identity()).first()

    users = db.query(User).all()
    users = [i.toJSON() for i in users]

    return {
        'users': users,
        'auth_user': authuser.toJSON()
    }, 200

@app.route("/signup", methods=["POST"])
def signup():
    
    try:

        data = request.get_json()

        if not data.get("email", None) or not data.get("password", None):
            return {"error": "Invalid data"}, 400
        
        new_user = User(
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            email=data["email"]
        )

        new_user.set_password(data["password"])
        db.add(new_user)
        db.commit()

        return {
            "data": new_user.toJSON(),
            "message": "success"
        }, 201
    
    except Exception as e:
        if 'UNIQUE constraint failed' in str(e):
            return {'message': 'Email already exists'}, 400
        
        return {'error': str(e)}, 400
    
@app.route("/signin", methods=["POST"])
def signin():
    data = request.get_json()

    if not data.get("email", None) or not data.get("password", None):
        return {"error": "Invalid data"}, 400
    
    user = User.query.filter_by(email=data['email']).first()

    if user:
        if user.check_password(data["password"]):
            access = create_access_token(identity=user.id)
            refresh = create_refresh_token(identity=user.id)
            return {
                "message": "Logged In Successful",
                "access_token": access,
                "refresh_token": refresh
            }, 200
        return {
            "error": "Invalid Credentials"
        }, 400

    return {
        "error": "Invalid Credentials"
    }, 400

@app.route("/refresh", methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access = create_access_token(identity=current_user)
    return {
        "access_token": access
    }

if __name__ == "__main__":
    app.run(debug=True, port = 8000)