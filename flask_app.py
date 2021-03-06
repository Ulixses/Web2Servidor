import os
from flask import render_template, request, redirect, url_for, flash, send_from_directory
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_moment import Moment

from flask_login import LoginManager, login_required, login_user, current_user, logout_user
from flask_mail import Mail, Message
from sqlalchemy import desc
from models import models
from forms import forms
from flask_admin import Admin,AdminIndexView
from flask_admin.contrib.sqla import ModelView

import json
import datetime
from random import randrange
with open('configuration.json') as json_file:
    configuration = json.load(json_file)

print("FLASK_APP.PY:", __name__)

app = models.app
db = models.db


Bootstrap(app)

moment = Moment(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
user_type =["admin","empleado","desafiante","jugador" ]

class AdminView(AdminIndexView):
    def is_accessible(self):
        if current_user.is_authenticated and current_user.type_user in {0,1}:
            return True
        return False


admin = Admin(template_mode='bootstrap3', index_view=AdminView())


admin.init_app(app)


app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = configuration['gmail_username']
app.config['MAIL_PASSWORD'] = configuration['gmail_password']

app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[U-TAD Prog. Web II - Servidor] '
app.config['FLASKY_MAIL_SENDER'] = 'Graciano y Ulises'

mail = Mail(app)

def send_email(to, subject, template, url,**kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject, sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs,base_url=url)
    mail.send(msg)


"""
user1 = User(username='manoel',email='manoel.alonso@u-tad.com',password='12345678')
db.session.add(user1)
db.session.commit()


user2 = User(username='manoel2', email='manoel2.alonso@u-tad.com',password='12345678')
db.session.add(user2)
db.session.commit()

user = User.query.filter_by(id=1).first()
"""

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

@app.route('/')
def index():
    competiciones = models.Competition.query.all()
    return render_template("react/index_react.html", page="index", current_time=datetime.datetime.now(), competiciones = competiciones)

###############################################################################################################
#         REACT-IMPROVEMENTS                                                                         START    #
###############################################################################################################

@app.route('/competiciones')
def competiciones():
    competiciones = models.Competition.query.all()
    comp_json = []
    numbers = [0]
    for row in competiciones:
        i = 0
        score = " - "
        while i in numbers:
            i = randrange(0,15)
        numbers.append(i)
        total = models.Prediction.query.filter_by(competioncode = row.competioncode).count()
        max_score = models.Prediction.query.filter_by(competioncode = row.competioncode).order_by(models.Prediction.score.desc()).first()
        if(type(max_score) != type(None)):
            score = round(max_score.score,1)
        comp_json.append(
            {
                "code": row.competioncode,
                "descripcion": row.descripcion,
                "username": row.username,
                "number" : i,
                "fin" :  row.final_date.strftime("%d-%m-%Y"),
                "total": total,
                "max_score" : score
            }
        )
    print(comp_json)
    users_first = models.Prediction.query.filter_by(competioncode = comp_json[0]["code"]).all()
    print([i.username for i in users_first])
    return jsonify(comp_json)

@app.route('/images/<image>')
def images(image):
    return send_from_directory('./static/images', image)

###############################################################################################################
#         REACT-IMPROVEMENTS                                                                          END     #
###############################################################################################################

@app.route('/login', methods=['GET','POST'])
def login():
    form = forms.LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                user = models.User.query.filter_by(username=form.username.data).first()
                if (user == None):
                    flash('Wrong user or password.')
                elif  user.confirmed == 0:
                    flash('Email address has not been confirmed. Please visit your email to confirm your user before logging in.')
                elif check_password_hash(user.password,form.password.data):
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('dashboard'))
                else:
                    flash('Access denied - wrong username or password')
            except:
                flash('Access denied - wrong username or password')
    else:
        pass
    return render_template("react/login_react.html",page="login", form=form)

import random
@app.route('/signup', methods=['GET','POST'])
def signup():
    form = forms.RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                password_hashed = generate_password_hash(form.password.data,method='sha256')
                print("pass has")
                new_user = models.User(username=form.username.data,
                                email=form.email.data,
                                password=password_hashed,
                                userhash=str(random.getrandbits(128)),
                                type_user = int(form.type_user.data))
                print(form.type_user)
                print("modelo introducido bd")
                send_email(new_user.email,'Por favor, confirmar correo.','mail/new_user',user=new_user,url=request.host)
                print("email enviado")
                db.session.add(new_user)
                print("usuario inicia")
                db.session.commit()
                flash("User created successfully")
                return redirect(url_for('login'))
            except:
                db.session.rollback()
                flash("Something went wrong. User has not been created. Please try again.")
    return render_template("react/signup_react.html", page="signup", form=form)

@app.route('/confirmuser/<username>/<userhash>', methods=['GET'])
def confirmuser(username,userhash):
    form = forms.LoginForm()
    user = models.User.query.filter_by(username=username).first()
    if user == None:
        flash('Invalid url.')
    elif user.userhash != userhash:
        flash('Invalid url.')
    else:
        user.confirmed = 1
        db.session.commit()
        flash('Email validated, please log in.')

    return render_template("login.html", page="login", form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    if(current_user.type_user in [0,1]):
        return redirect('/admin')
    elif(current_user.type_user ==2):
        user_table_creadas = models.Competition.query.filter_by(username =  current_user.username)
        user_table_jugando = models.Prediction.query.filter_by(username =  current_user.username)
        print(2)
        print(current_user.username)
        for i in user_table_creadas:
            print(i)
        return render_template("dashboard.html", page="dashboard",current_user=current_user, rows_competiciones_creadas = user_table_creadas,rows_competiciones_jugando =  user_table_jugando)
    elif(current_user.type_user ==3):
        user_table_jugando = models.Prediction.query.filter_by(username =  current_user.username)
        for i in user_table_jugando:
            print(i)
        return render_template("dashboard.html", page="dashboard",current_user=current_user, rows_competiciones_jugando = user_table_jugando)

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():

    if request.method == 'GET': # Cargando los datos del usuario
        user = models.User.query.filter_by(username=current_user.username).first()
        form = forms.ProfileForm(username=user.username,
                            email=user.email,
                            type_user = user_type[user.type_user])
    elif request.method == 'POST':  # Actualizar los datos del usuario
        form = forms.ProfileForm()
        if form.validate_on_submit():
            #return("1.2")
            if current_user.username != form.username.data:
                flash('No tienes permiso para actualizar estos datos.')
                return redirect(url_for('index'))
            user = models.User.query.filter_by(username=current_user.username).first()
            user.email = form.email.data
            if form.password.data != '':
                user.password = generate_password_hash(form.password.data,method='sha256')
            db.session.commit()
            flash('Datos actualizados con exito')
    else:
        return redirect(page_not_found('Tipo de llamada inexistente.'))
    competitions = models.Competition.query.all()
    datos = {}
    if current_user.type_user == 2:
        datos["comp_total"] = models.Competition.query.filter_by(username=current_user.username).count()
    elif  current_user.type_user == 3:
        pass
    datos["pred_total"] = models.Prediction.query.filter_by(username=current_user.username).count()
    datos["part_total"] = models.Prediction.query.with_entities(models.Prediction.competioncode).filter_by(username=current_user.username).distinct().count()
    datos["max_score"] = models.Prediction.query.filter_by(username=current_user.username).order_by(models.Prediction.score.desc()).first().score
    if type(datos["max_score"]) == type(None):
        datos["max_score"] = 0
    return render_template("profile.html", page="profile",current_user=current_user, form=form, rows=competitions, data=datos)


### FILE MANAGER  - START
#ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xlsm', 'xls', 'csv', 'dat','zip', 'tar', 'gz', '7z', 'doc', 'docx', 'ppt', 'pptx','rar'])
ALLOWED_EXTENSIONS = set(['csv'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS

import pandas as pd

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():

    if current_user.type_user != 2:
        return redirect(url_for('dashboard'))
    form = forms.UploadForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            num_files = 0
            errors = 0
            if (len(request.files.getlist('file')) != 2):
                flash('Por favor subir 2 ficheros. El fichero de entrenamiento y el fichero de test. Usted ha subido {} ficheros.'.format(len(request.files.getlist('file'))))
                return render_template("upload.html", page="upload",current_user=current_user, form=form)

            file_obj = request.files.getlist('file')[0]
            filename_secured = secure_filename(file_obj.filename)
            if allowed_file(filename_secured) is False:
                flash("Documento {} no es válido. Los documentos válidos son: {}". \
                    format(str(filename_secured), ALLOWED_EXTENSIONS))
                errors += 1
            else: # FICHERO APROBADO!
                num_files += 1
                file_path = './uploads/temp1.csv'
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                finally:
                    file_obj.save(file_path)
                df1 = pd.read_csv(file_path)

            file_obj = request.files.getlist('file')[1]
            filename_secured = secure_filename(file_obj.filename)
            if allowed_file(filename_secured) is False:
                flash("Documento {} no es válido. Los documentos válidos son: {}". \
                    format(str(filename_secured), ALLOWED_EXTENSIONS))
                errors += 1
            else: # FICHERO APROBADO!
                num_files += 1
                file_path = './uploads/temp2.csv'
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                finally:
                    file_obj.save(file_path)
                df2 = pd.read_csv(file_path)

            if errors != 0:
                flash('Me has enviado alguno(s) ficheros - errores: {} / correcto: {} !'.format(errors,num_files))
                competitions = models.Competition.query.all()
                return render_template("upload.html", page="upload",current_user=current_user, rows=competitions, form = form)
                
            if len(df1) > len(df2):
                df_train, df_test = df1, df2
            else:
                df_train, df_test = df2, df1

    #        df_test_public = df_test.iloc[:,:-1]
    #        df_test_private = df_test.iloc[:,-1]

            df_test_public = df_test.iloc[:,:-1]
            df_test_private = df_test.copy().drop(columns=df_test.columns[0:-1])


            competioncode =  ''.join(random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVYXZabcdefghijklmnopqrstuvyxz') for i in range(10))
            filename_prefix = current_user.username+"__" +  str(competioncode)

            df_train.to_csv('./static/uploads/'+filename_prefix+"__train.csv")
            df_test_public.to_csv('./static/uploads/'+filename_prefix+"__test.csv")
            df_test_private.to_csv('./uploads/'+filename_prefix+"__test_private.csv")


            new_competition = models.Competition(competioncode=competioncode,
                            username=current_user.username,
                            inicio_date = form.dia_inicio.data,
                            final_date = form.dia_fin.data,
                            intervalo_subida = form.intervalo_subida.data,
                            num_max_intentos = form.intentos_diarios.data,
                            descripcion = form.descripcion.data)
            db.session.add(new_competition)

            new_df_train = models.File(username=current_user.username,
                            competioncode=competioncode,
                            filename=filename_prefix+"__train.csv"
                            )
            db.session.add(new_df_train)

            new_df_test_public = models.File(username=current_user.username,
                            competioncode=competioncode,
                            filename= filename_prefix+"__test.csv"
                            )
            db.session.add(new_df_test_public)

            new_df_test_private = models.File(username=current_user.username,
                            competioncode=competioncode,
                            filename= filename_prefix+"__test_private.csv"
                            )
            db.session.add(new_df_test_private)


            db.session.commit()
            flash("Competición {} creata con éxito.".format(competioncode))
            flash('Me has enviado alguno(s) ficheros - errores: {} / correcto: {} !'.format(errors,num_files))
    #    else:
    #        return redirect(page_not_found('Tipo de llamada inexistente.'))

    #competitions = models.Competition.query.filter_by(username=current_user.username).all()
    competitions = models.Competition.query.all()
    return render_template("react/upload_react.html", page="upload",current_user=current_user, rows=competitions, form = form)


@app.route('/files/<competioncode>', methods=['GET','POST'])
@login_required
def files(competioncode):
#    return("Muy bien el enlace funciona para la competición {}".format(competioncode))
    files = models.File.query.filter_by(competioncode=competioncode).all()
    return render_template("files.html", page="files",current_user=current_user,rows=files)

@app.route('/code/<competioncode>', methods=['GET','POST'])
@login_required
def code(competioncode):
    competioncode = competioncode.replace(".py","")
    competion = models.Competition.query.filter_by(competioncode=competioncode).first()
#    if competion == None:
#        return("es vacio")
#    else:
#        return("no es vacio")
    return render_template("competition_template.py",competion=competion,current_user=current_user, base_url=request.host )


@app.route('/ranking/<competioncode>', methods=['GET'])
def ranking(competioncode):
    files = models.File.query.filter_by(competioncode=competioncode).first()
    best_predictions = models.Prediction.query.filter_by(competioncode=competioncode).order_by(desc(models.Prediction.score)).all()
    competicion = models.Competition.query.filter_by(competioncode=competioncode).first()
    print(best_predictions)
    return render_template("ranking.html", page="ranking",current_user=current_user, rows=best_predictions, file=files, competicion=competicion )



###############################################################################################################
#         API-REST -                                                                                START    #
###############################################################################################################
from flask_httpauth import HTTPBasicAuth
from flask import abort, jsonify, make_response
auth = HTTPBasicAuth()

API_USER_SESSION = {}

@auth.verify_password
def verify_pw(username, password):
    global API_USER_SESSION
    try:
        API_USER_SESSION["username"]= username

        user = models.User.query.filter_by(username=username).first()
        if user.password == password:
            return True
    except:
        abort(401)
    return False

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

@app.route('/favicon.ico')
def favicon():
    return("")


from sklearn.metrics import roc_auc_score
@app.route('/uploadpredictions/<competioncode>', methods=['POST'])
@auth.login_required
def uploadpredictions(competioncode):
    global API_USER_SESSION
#    return('/uploadpredictions/{}'.format(competioncode))

    if 'file' not in request.files:
        return ('ERROR: no file part')
    file_obj = request.files['file']
    if file_obj.filename == '':
        return ('ERROR: no selected file')


    competition = models.Competition.query.filter_by(competioncode=competioncode).first()
    fecha_incio = competition.inicio_date
    fecha_fin = competition.final_date
    df_private    = pd.read_csv('./uploads/{}__{}__test_private.csv'.format(competition.username,competioncode))
    df_private.columns = ['id','real']
    df_private.index = df_private.id
    now = datetime.datetime.now()
    print(fecha_incio.year,">", int(now.strftime("%Y")) ,fecha_incio.month, ">",int(now.strftime("%-m")),fecha_incio.day, ">",int(now.strftime("%-d")))
    print(fecha_fin.year,"<", int(now.strftime("%Y")) ,fecha_fin.month, "<",int(now.strftime("%-m")),fecha_fin.day, "<",int(now.strftime("%-d")))
    if(fecha_incio.year>=int(now.strftime("%Y")) and fecha_incio.month>=int(now.strftime("%-m")) and fecha_incio.day>int(now.strftime("%-d"))):
        return ("ERROR: enviado antes de la fecha de incio")
    if(fecha_fin.year<=int(now.strftime("%Y")) and fecha_fin.month<=int(now.strftime("%-m")) and fecha_fin.day<int(now.strftime("%-d"))):
        return ("ERROR: enviado despues de fecha de cierre")
#    return('len(df_private) ={}'.format(len(df_private)))
    predicciones = models.Prediction.query.filter_by(competioncode = competioncode,username = API_USER_SESSION['username'])
    cont = 0
    for i in predicciones:
        fecha = i.creation_date
        print(fecha.year,"=", int(now.strftime("%Y")) ,fecha.month, "=",int(now.strftime("%-m")),fecha.day, "=",int(now.strftime("%-d")))
        if(fecha.year==int(now.strftime("%Y")) and fecha.month==int(now.strftime("%-m")) and fecha.day==int(now.strftime("%-d"))):
            cont += 1
    if(cont >= competition.num_max_intentos):
        return ("ERROR: Sobrepasado el numero de intetos")
    tiempo_seg = int(competition.intervalo_subida)
    seg_act = -1
    for i in predicciones:
        fecha = i.creation_date
        print(fecha.year,">", int(now.strftime("%Y")) ,fecha.month, ">",int(now.strftime("%-m")),fecha.day, ">",int(now.strftime("%-d")), fecha.hour , ">",int(now.strftime("%-H")), fecha.minute , ">",int(now.strftime("%-M")), fecha.second , ">", seg_act)

        print("Fechas 1:", now, fecha)
        if(fecha.year==int(now.strftime("%Y")) and fecha.month==int(now.strftime("%-m")) and fecha.day==int(now.strftime("%-d"))\
        and fecha.hour ==int(now.strftime("%-H")) and fecha.minute ==int(now.strftime("%-M")) and fecha.second > seg_act):
                 seg_act = fecha.second
    print("Fechas 2:", int(now.strftime("%-S")), seg_act)
    if(int(now.strftime("%-S")) - seg_act < tiempo_seg and seg_act != -1):
        return ("ERROR: Intentos demasiados segidos espera un poco")
    file_path = './uploads/submission_temp.csv'
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
    finally:
        file_obj.save(file_path)

    try:
        df_submission = pd.read_csv(file_path)
        df_submission.index = df_submission.id
    except:
        return ('ERROR: file empty or not a valid csv')

    df_merged = pd.merge(df_private, df_submission, left_index=True, right_index=True, how='left')
    df_merged.fillna(0, inplace=True)
#    gini_score = str(float(2*roc_auc_score(df_merged.real, df_merged.pred)-1))
    gini_score = float(2*roc_auc_score(df_merged.real, df_merged.pred)-1)


#    try:
#    return("""new_prediction = models.Prediction(competioncode = 'ASDASDAS', username = 'mgadi', score = 0.65, metrica = 'gini')""")
#    new_prediction = models.Prediction(competioncode = 'ASDASDAS', username = 'mgadi', score = 0.65, metrica = 'gini')

#    return(("1:"+str(type(gini_score)))+" / 2:" + str(type(float(gini_score))))

    new_prediction = models.Prediction(competioncode = competioncode, username = API_USER_SESSION['username'], score = gini_score, metrica = 'gini')
    db.session.add(new_prediction)
    db.session.commit()
#    except:
#        db.session.rollback()

    #quiero guardar esta información
    #API_USER_SESSION['username']
    #gini_score

#    return('len(df_submission.columns)={} / len(df_private) ={}'.format(len(df_submission),len(df_private)))
    return("Enhorabuena has enviado una predicción a la competición {} - el gini obtenido es = {}".format(competioncode, gini_score))


@app.route('/logout')
#@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

'''@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html")
'''
#def internal_server_error(e):
#    return render_template("500.html")

if __name__ == '__main__':
    app.run(debug=1)
    #app.run()

#Todo lo relacionado con Admin
from wtforms.fields import PasswordField, SelectField
class ProtectedView(ModelView):
    def is_accessible(self):
        if current_user.is_authenticated and current_user.type_user in {0,1}:
            return True
        return False

class UserAdmin(ProtectedView):

    column_exclude_list = ('password')
    form_excluded_columns = ('password')
    column_auto_select_related = True
    def scaffold_form(self):
        form_class = super(UserAdmin, self).scaffold_form()
        form_class.password2 = PasswordField('New Password')
        return form_class
    def on_model_change(self, form, model, is_created):
        if len(model.password2):
            model.password = generate_password_hash(model.password2,method='sha256')
    def is_accessible(self):
        return current_user.is_authenticated and current_user.type_user == 0

class UserEmpleados(UserAdmin):

    column_exclude_list = ('password')
    form_excluded_columns = ('password','type_user')
    column_auto_select_related = True
    def scaffold_form(self):
        form_class = super(UserEmpleados, self).scaffold_form()
        form_class.password2 = PasswordField('New Password')
        form_class.type_user2 = SelectField("Tipo de usuario", choices=[(2,"Desafiante"),(3,"Jugador")] ,validators = None, coerce  =  int)
        return form_class
    def on_model_change(self, form, model, is_created):
        if model.type_user2 not in [2,3]:
            delete_form()
        else:
            model.type_user = model.type_user2
        if len(model.password2):
            model.password = generate_password_hash(model.password2,method='sha256')
    def is_accessible(self):
        return current_user.is_authenticated and current_user.type_user == 1

from flask_admin.menu import MenuLink

admin.add_view(UserAdmin(models.User, db.session))
admin.add_view(UserEmpleados(models.User, db.session, endpoint="players"))
admin.add_view(ProtectedView(models.File, db.session))
admin.add_view(ProtectedView(models.Competition, db.session))
admin.add_view(ProtectedView(models.Prediction, db.session))
admin.add_link(MenuLink(name='Logout',category="", url='/logout'))
admin.add_link(MenuLink(name='Go back',category="", url='/'))
