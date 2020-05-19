from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField,MultipleFileField,IntegerField#,DateField
from wtforms.validators import InputRequired, Length, Email, NoneOf, Regexp

from wtforms.fields.html5 import DateField




class LoginForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[InputRequired(), Length(min=4, max=15)])

    password = PasswordField('Contraseña', validators=[InputRequired(), Length(min=4, max=80)])

    remember = BooleanField('Recuérdame')


class RegisterForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[InputRequired(),
                                                            Length(min=4, max=15),
                                                            NoneOf(['pepito','juanito'],
                                                            message='Usuario ya existe')])

    password = PasswordField('Contraseña',validators=[InputRequired(), Length(min=8, max=80)])

    email = StringField('E-mail',validators=[InputRequired(), Email(message='Email inválido') ,
                                             Length(max=50)])

    dni = StringField('DNI o un NIE',validators=[InputRequired(),
                                             Length(max=9),
                                             Regexp('^([a-z]|[A-Z]|[0-9])[0-9]{7}[a-zA-Z]$')])

    type_user = SelectField("Tipo de usuario", choices=[(2,"Desafiante"),(3,"Jugador")] ,validators = None, coerce  =  int)


class ProfileForm(FlaskForm):
    username = StringField('Nombre de usuario',validators=[InputRequired(), Length(min=4, max=15),
                                                   NoneOf(['pepito','juanito'],
                                                          message='Usuario ya existe')])

    email = StringField('E-mail',validators=[InputRequired(), Email(message='Invalid email') ,
                                             Length(max=50)])

    password = PasswordField('Contraseña')

    dni = StringField('DNI o un NIE',validators=[InputRequired(),
                                             Length(max=9),
                                             Regexp('^([a-z]|[A-Z]|[0-9])[0-9]{7}[a-zA-Z]$')])

    silo = StringField('Grupo asignado',validators=[InputRequired(),
                                             Length(max=9)])
class UploadForm(FlaskForm):
    descripcion = StringField('Descripcion',validators= None)
    intentos_diarios = IntegerField('Intentos diarios' ,validators= None)
    dia_inicio = DateField('Dia de inicio',validators= None)
    dia_fin = DateField('Dia de inicio',validators= None)


