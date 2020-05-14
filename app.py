# -*- coding: utf-8 -*-
"""
Created on Thu Feb 27 13:29:32 2020

@author: manoel.alonso
"""

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField#, SelectField
from wtforms.validators import InputRequired, Length, Email, NoneOf#, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_moment import Moment
from datetime import datetime
from flask_login import LoginManager, login_required, login_user, UserMixin
from flask_migrate import Migrate 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'EstoDeflask_wtfEsLaPolla!'
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./database/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)
moment = Moment(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

migrate = Migrate(app,db)

"""
user1 = User(username='manoel',email='manoel.alonso@u-tad.com',password='12345678')    
db.session.add(user1)
db.session.commit()


user2 = User(username='manoel2', email='manoel2.alonso@u-tad.com',password='12345678')    
db.session.add(user2)
db.session.commit()

user = User.query.filter_by(id=1).first()
"""
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader    
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('User Name',validators=[InputRequired(), Length(min=4,max=15)])
    password = PasswordField('Password',validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    username = StringField('User Name',validators=[InputRequired(), Length(min=4, max=15),
                                                   NoneOf(['pepito','juanito'],
                                                          message='Usuario ya existe')])
    password = PasswordField('Password',validators=[InputRequired(), Length(min=8, max=80)])
    #,Regexp('^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$')])
                                                        
    email = StringField('E-mail',validators=[InputRequired(), Email(message='Invalid email') ,
                                             Length(max=50)])
#    language = SelectField('Programming Language')    
#    language = SelectField('Programming Language', choices=[('cpp', 'C++'), 
#                                                             ('py', 'Python'), 
#                                                             ('text', 'Plain Text')])

@app.route('/')
def index():
    return render_template("index.html", page="index", current_time=datetime.utcnow())

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                user = User.query.filter_by(username=form.username.data).first()
    #            return "usenname={}; password_bd={}; password_enviada={}".format(user.username,user.password,form.password.data)
                if user != None and check_password_hash(user.password,form.password.data):
                    login_user(user, remember=form.remember.data)                
                    return redirect(url_for('dashboard'))
                else:
                    flash('Access denied - wrong username or password')
            except:
                flash('Access denied - wrong username or password')
    else:
        pass
    return render_template("login.html", page="login", form=form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
#    form.language.choices = [('pc', 'Pascal'), ('cb', 'Cobol'),('jv', 'Java')]
    
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                password_hashed = generate_password_hash(form.password.data,method='sha256')
                new_user = User(username=form.username.data,
                                email=form.email.data,
                                password=password_hashed)    
                db.session.add(new_user)
                db.session.commit()
                flash("User created successfully")
                return redirect(url_for('login'))
            except:
                flash("Something went wrong. User has not been created. Please try again.")
    return render_template("signup.html", page="signup", form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", page="dashboard")

@app.route('/logout')
@login_required
def logout():
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html")

if __name__ == '__main__':
    app.run(debug=True)
    #app.run()