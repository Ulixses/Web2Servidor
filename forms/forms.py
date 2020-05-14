from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField#, SelectField
from wtforms.validators import InputRequired, Length, Email, NoneOf, Regexp

class LoginForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4,max=15)])
    password = PasswordField('Contraseña',validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Recuérdame')

class RegisterForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4, max=15),
                                                   NoneOf(['pepito','juanito'],
                                                          message='Usuario ya existe')])
    password = PasswordField('Contraseña',validators=[InputRequired(), Length(min=8, max=80)])
    #,Regexp('^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$')])

    email = StringField('E-mail',validators=[InputRequired(), Email(message='Email inválido') ,
                                             Length(max=50)])
#    language = SelectField('Programming Language')
#    language = SelectField('Programming Language', choices=[('cpp', 'C++'),
#                                                             ('py', 'Python'),
#                                                             ('text', 'Plain Text')])

    dni = StringField('DNI o un NIE',validators=[InputRequired(),
                                             Length(max=9),
                                             Regexp('^([a-z]|[A-Z]|[0-9])[0-9]{7}[a-zA-Z]$')])

class ProfileForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4, max=15),
                                                   NoneOf(['pepito','juanito'],
                                                          message='Usuario ya existe')])

    email = StringField('E-mail',validators=[InputRequired(), Email(message='Invalid email') ,
                                             Length(max=50)])
#    language = SelectField('Programming Language')
#    language = SelectField('Programming Language', choices=[('cpp', 'C++'),
#                                                             ('py', 'Python'),
#                                                             ('text', 'Plain Text')])
    password = PasswordField('Contraseña')

    dni = StringField('DNI o un NIE',validators=[InputRequired(),
                                             Length(max=9),
                                             Regexp('^([a-z]|[A-Z]|[0-9])[0-9]{7}[a-zA-Z]$')])

    silo = StringField('Grupo asignado',validators=[InputRequired(),
                                             Length(max=9)])

