from flask import Flask
from flask_login import UserMixin
from flask_sqlalchemy  import SQLAlchemy
import json

print(__name_)
app = Flask(__name__)

with open('/home/manoelutad/configuration.json') as json_file:
    configuration = json.load(json_file)

app.config['SECRET_KEY'] = configuration['SECRET_KEY']



SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username=configuration['mysql_username'],
    password=configuration['mysql_password'],
    hostname=configuration['mysql_hostaname'],
    databasename=configuration['mysql_databasename'],
)


app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    confirmed = db.Column(db.Integer, default=0)
    userhash = db.Column(db.String(50))
    dni = db.Column(db.String(9))
    silo = db.Column(db.String(9))






