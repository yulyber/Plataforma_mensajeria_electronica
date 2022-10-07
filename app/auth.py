from ast import Import
import functools
import random
from turtle import clear
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

#Permite confirmar links de activación sin confirmar para luego crear el usuario correspondiente.
@bp.route('/activate', methods=['GET', 'POST'])
def activate(): 
    try:
        if g.user: #si hay un usuario en sesion lo redirecciona al inbox
            return redirect(url_for('inbox.show'))
        
        if request.method == "GET": #ya que la URL de activación trae parametros es GET
            number = request.args['auth'] #almacena el valor del auth en number, este representa la columna Challange en la base de datos
            
            db = get_db()#obtiene la base de datos  
            attempt = db.execute(
            'select * from activationlink WHERE challenge=? and state=? ',  #consulta si hay un link de activación relacionado al number que aun no este confirmado
            (number, utils.U_UNCONFIRMED)
            ).fetchone()

            if attempt is not None: #Si la variable NO esta vacia

                db.execute(
                'UPDATE activationlink SET state=? WHERE id =?', #Confirma el link de activación con el id correspondiente, garantizando que sea de un solo uso
                (utils.U_CONFIRMED, attempt['id'])
                )

                db.execute(
                'INSERT INTO user(username, password,salt,email) VALUES  (?,?,?,?)',  #crea un usuario con la información del link de activación
                (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])
                )

                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=["GET","POST"])
def register():
    try:
        if g.user:#si hay un usuario en sesion lo redirecciona al inbox
            return redirect(url_for('inbox.show'))
        
        if request.method == "POST":    
            #Se traen los datos del formulario refernciando al id 
            username = request.form["username"]
            password = request.form["password"]
            email = request.form["email"]
            
            db = get_db()  #Obtiene la conexión a la base de datos
            #Se instancia la variable error con valor None, para ser llenada en caso de encontrar un error
            error = None

            if not username:#Si la variable esta vacia 
                error = 'Se requiere nombre de usuario.'
                flash(error)
                return render_template("auth/register.html")
            
            if not utils.isUsernameValid(username): #valida que el nombre de usuario sea valido segun la libreria Utils
                error = "El nombre de usuario debe ser alfanumérico más '.','_','-'"
                flash(error)
                return render_template("auth/register.html")

            if not password: #Si la variable esta vacia 
                error = 'Se requiere contraseña.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute(
                'SELECT id FROM user WHERE username = ?',  #Consulta si existe un usuario con ese nombre con el fin de garantizar que sea unico
                (username,)).fetchone() is not None:

                error = 'El usuario {} ya está registrado.'.format(username)
                flash(error)
                return render_template("auth/register.html")
            
            if (not email or (not utils.isEmailValid(email))): #Si la variable esta vacia  o no tiene la estructura de un correo valido
                error =  'Dirección de correo electrónico no válida.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute(
                'SELECT id FROM user WHERE email = ?', #consulta si hay existe un usuario con ese email, garantizando que sea unico
                (email,)).fetchone() is not None:
                error =  'El correo electrónico {} ya está registrado.'.format(email)
                flash(error)
                return render_template("auth/register.html")
            
            if (not utils.isPasswordValid(password)): #si la contraseña no cumple con la estructura valida segun la libreria utils
                error = 'La contraseña debe contener al menos una letra minúscula, una letra mayúscula y un número con 8 caracteres de longitud'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:] #Genera numero aleatorio y lo combierte en hexadecimal 
            hashP = generate_password_hash(password + salt) #codifica la contraseña teniendo en cuentra el Salt
            number = hex(random.getrandbits(512))[2:] #Genera numero aleatorio y lo combierte en hexadecimal 

            db.execute(
            #crea en la tabla activationlink un registro que se considera no confirmado, manda la clave cifrada y el factor Salt, entre otros datos
            'INSERT INTO activationlink(challenge, state,username,password,salt,email) VALUES (?,?,?,?,?,?)',
            (number, utils.U_UNCONFIRMED, username, hashP, salt, email))

            db.commit()

            credentials = db.execute(
            'SELECT user,password FROM credentials WHERE name=?',  #consulta los datos del correo con que se envian los mesajes
            (utils.EMAIL_APP,)
            ).fetchone()

            #contenido del correo y el creación del link de activación
            content = 'Hola, para activar su cuenta, haga clic en este enlace ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            #envia el correo
            send_email(credentials, receiver=email, subject='Activa tu cuenta', message=content)
            
            flash('Por favor revise su correo electrónico registrado para activar su cuenta')
            return render_template('auth/login.html') 

        return render_template("auth/register.html") 
    except:
        return render_template('auth/register.html')

#Se usa para actualizar la nueva contraseña e inactivar el forgotlink usado
@bp.route('/confirm', methods=["GET", "POST"]) 
def confirm():
    try:
        if g.user:#si hay un usuario en sesion lo redirecciona al inbox
            return redirect(url_for('inbox.show'))

        if request.method =="POST": #Se traen los datos del formulario refernciando al id 
            password = request.form["password"]
            password1 = request.form["password1"]
            authid = request.form['authid'] #campo oculto que ayuda a identificar el link

            if not authid: #Si la variable esta vacia 
                flash('Inválido')
                return render_template('auth/forgot.html')

            if not password: #Si la variable esta vacia 
                flash('Se requiere contraseña')
                return render_template('auth/change.html', number=authid)

            if not password1:#Si la variable esta vacia 
                flash('Se requiere confirmación de contraseña')
                return render_template('auth/change.html', number=authid)

            if password1 != password:#si las contraseñas no coinciden
                flash('Ambos valores deben ser iguales')
                return render_template('auth/change.html', number=authid)

            if not utils.isPasswordValid(password): #si la contraseña no tiene la estructura
                error = 'La contraseña debe contener al menos una letra minúscula, una letra mayúscula y un número con 8 caracteres de longitud.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db() #Obtiene la conexión a la base de datos
            attempt = db.execute(
            'select * from forgotlink where challenge =? and state=?;',  #trae el forgotlink que concida con el number enviado en el correo y que este activo
            (authid, utils.F_ACTIVE) 
            ).fetchone()
            
            if attempt is not None: #Si la variable NO esta vacia
                db.execute(
                'UPDATE forgotlink SET state=? WHERE id =?', #inactiva el forgotlink que tenga el id
                (utils.F_INACTIVE, attempt['id'])
                )

                salt = hex(random.getrandbits(128))[2:] #genera un nuevo salt
                hashP = generate_password_hash(password + salt)  #codifica la nueva contraseña

                db.execute(
                'UPDATE user SET password=?, salt=? WHERE id =?', #actualiza la nueva contraseña y el salt usado
                (hashP, salt, attempt['userid'])
                )

                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Inválido')
                return render_template('auth/forgot.html')

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')

#Valida exista un forgotlink activo de ser asi redirecciona para cambiar la contraseña
@bp.route('/change', methods=['GET', 'POST']) 
def change():
    try:
        if g.user:  #si hay un usuario en sesion lo redirecciona al inbox
            return redirect(url_for('inbox.show'))
        
        if request.method == "GET": 
            number = request.args['auth'] 
            
            db = get_db() #Obtiene la conexión a la base de datos
            attempt = db.execute(
            'select * from forgotlink where challenge =? and state=?',  #consulta si hay un forgotlink activo
            (number, utils.F_ACTIVE)
            ).fetchone()
            #Si la variable NO esta vacia
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')

#Inactiva forgotlink existentes y crea uno nuevo el cual envia por correo
@bp.route('/forgot', methods=['GET', 'POST'])
def forgot():
    try:
        if g.user:  #si hay un usuario en sesion lo redirecciona al inbox
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            #Se traen los datos del formulario refernciando al id 
            email = request.form['email'] 
            
            if (not email or (not utils.isEmailValid(email))): #si la variable esta vacia o el correo no tiene una estructura valida segun la libreria utils
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db() #Obtiene la conexión a la base de datos
            user = db.execute(
            'SELECT * FROM user WHERE email=?', #Obtiene el usuario que coincide con el correo
            (email,) 
            ).fetchone()

            if user is not None: #Si la variable NO esta vacia
                number = hex(random.getrandbits(512))[2:]  #Genera numero aleatorio y lo combierte en hexadecimal 
                
                db.execute(
                'UPDATE forgotlink SET state=? WHERE id =?',#Inactiva forgotlinks relacioandos al usuario
                (utils.F_INACTIVE, user['id'])                     
                )

                db.execute(
                'INSERT INTO forgotlink(userid, challenge,state) VALUES (?,?,?)',# crea un nuevo forgotlink activo
                (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                'SELECT user,password FROM credentials WHERE name=?', #obtiene las credenciales de la cuenta para enviar el correo
                (utils.EMAIL_APP,) 
                ).fetchone()
                #contenido del correo y genera la URL para cambiar la contraseña
                content = 'Hola, para cambiar su contraseña, por favor haga clic en este enlace ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                #envia el correo
                send_email(credentials, receiver=email, subject='Nueva contraseña', message=content)
                
                flash('Por favor verifique en su correo electrónico registrado')
            else:
                error = 'El correo electrónico no está registrado'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')

#valida que un usuario existe en la base de datos y lo redirecciona
@bp.route('/login', methods=["GET" , "POST"])
def login():
    try: 
        if g.user:
            return redirect(url_for('inbox.show')) #si hay un usuario en sesion lo redirecciona al inbox

        if request.method == "POST":
            #Se traen los datos del formulario referenciando al id 
            username = request.form["username"]
            password = request.form["password"]

            if not username:#Si la variable esta vacia 
                error = 'Campo de usuario requerido'
                flash(error)
                return render_template('auth/login.html')

            if not password:#Si la variable esta vacia 
                error = 'Campo de contraseña requerido'
                flash(error)
                return render_template('auth/login.html')

            db = get_db() #Obtiene la conexión a la base de datos
            error = None
            user = db.execute(
            'SELECT * FROM user WHERE username = ?', #trae los datos del usuario que tenga el username
            (username,)
            ).fetchone()
            
            if not user: #Si la variable esta vacia 
                error = 'Nombre de usuario o contraseña incorrecta'
            elif not check_password_hash(user['password'], password + user['salt']): #si la contraseña no coincide con la de la base de datos
                error = 'Nombre de usuario o contraseña incorrecta'   

            if error is None: #si no hay un error se limpia la sesion y se asigna el id del usuario que acaba de entrar
                session.clear()
                session['user_id'] = user["id"] 
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template("auth/login.html")
    except:
        return render_template('auth/login.html')
        
#si la sesion tiene un user_id se consultará en la db y se guardaran todos sun datos en g
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id") 

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
        'SELECT * FROM user WHERE id = ?', 
        (user_id,)
        ).fetchone()

#limpia la sesion y redirecciona       
@bp.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()