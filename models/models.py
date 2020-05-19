from flask import Flask
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

import json
from datetime import datetime

app = Flask('flask_app')

with open('configuration.json') as json_file:
    configuration = json.load(json_file)

app.config['SECRET_KEY'] = configuration['SECRET_KEY']

SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}?auth_plugin=mysql_native_password".format(
    username=configuration['mysql_username'],
    password=configuration['mysql_password'],
    hostname=configuration['mysql_hostaname'],
    databasename=configuration['mysql_databasename']
    )

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    confirmed = db.Column(db.Integer, default=0)
    userhash = db.Column(db.String(50))
    dni = db.Column(db.String(9))
    silo = db.Column(db.String(9))
    type_user = db.Column(db.Integer)#1:admin 2:empleado 3: challenger 4: player



class File(UserMixin, db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    competioncode = db.Column(db.String(15))
    filename = db.Column(db.String(50))
    creation_date = db.Column(db.DateTime, default=datetime.now)


class Competition(UserMixin, db.Model):
    __tablename__ = 'competitions'
    id = db.Column(db.Integer, primary_key=True)
    competioncode = db.Column(db.String(15), unique=True)
    username = db.Column(db.String(15))
    creation_date = db.Column(db.DateTime, default=datetime.now)
    inicio_date = db.Column(db.DateTime)
    final_date = db.Column(db.DateTime)
    num_max_intentos = db.Column(db.Integer)
    descripcion = db.Column(db.String(1000))

class Prediction(UserMixin, db.Model):
    __tablename__ = 'predictions'
    id = db.Column(db.Integer, primary_key=True)
    competioncode = db.Column(db.String(15))
    username = db.Column(db.String(15))
    score = db.Column(db.Float)
    metrica = db.Column(db.String(15))
    creation_date = db.Column(db.DateTime, default=datetime.now)




@app.before_first_request
def before_first_request():
    db.create_all()
    user = User.query.filter_by(username="admin").first()
    if user == None:
        password_hashed = generate_password_hash("admin",method='sha256')
        admin = User(username="admin",
                        password=password_hashed,
                        type_user = 0,
                        confirmed = 1)
        db.session.add(admin)
        db.session.commit()

# Ver los constraints en MYSQL:
# SELECT * FROM   information_schema.table_constraints WHERE  table_schema = schema() AND table_name = 'predictions';
