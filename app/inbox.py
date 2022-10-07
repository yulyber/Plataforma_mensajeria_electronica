from email import message
from pyexpat.errors import messages

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')

@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)

#Se encarga de consultar los mensajes
@bp.route('/show',) 
@login_required
def show():
        id = g.user['id'] #obtiene el id del usuario en sesion
        db = get_db() #llama a la base de datos
        messages = db.execute(
        "SELECT subject, username, created,body FROM message INNER JOIN user ON message.from_id = user.id  WHERE to_id =? or from_id=?", 
        (id,id)
        #Consulta en la base de datos los mensajes enviados por o para el usuario en sesion
        ).fetchall()
        
        return render_template("inbox/show.html", messages=messages)

#Se usa para crear mensajes
@bp.route('/send', methods=['GET', 'POST'])
@login_required
def send():
    
    if request.method == 'POST':
        #Se traen los datos del formulario refernciando al id     
        from_id = g.user['id']
        to_username = request.form["to"]
        subject = request.form["subject"]
        body = request.form["body"]

        db = get_db()#obtiene la conexión a la base de datos
               
        if not to_username: #Si la variable esta vacia 
            flash('El campo es obligatorio')
            return render_template("inbox/send.html")
        
        if not subject: #Si la variable esta vacia 
            flash('El campo de asunto es obligatorio')
            return render_template('inbox/send.html')
        
        if not body: #Si la variable esta vacia 
            flash('El campo del cuerpo es obligatorio')
            return render_template("inbox/send.html")    
        
        #Se instancia la variable error con valor None, para ser llenada en caso de encontrar un error
        error = None    
        userto = None 
        
        userto = db.execute(
        "SELECT * FROM user WHERE username = ?", #Trae toda la información del destinatario
        (to_username,)
        ).fetchone()
        
        if userto is None: #Si la variable esta vacia 
            error = 'El destinatario no existe'
     
        if error is not None: #Si la variable NO esta vacia 
            flash(error)

        else:

            db = get_db()            
            db.execute(
            "INSERT INTO message(from_id,to_id,subject,body) VALUES  (?,?,?,?)", #Crea un registro en la tabla mensajes con la información del formulario y de userto
            (from_id,  userto['id'], subject, body))           
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')