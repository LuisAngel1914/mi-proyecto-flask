from flask import jsonify
from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    get_jwt,
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)
from functools import wraps
from db import get_connection
from flask_cors import CORS
import os  # 🔥 NECESARIO PARA RENDER

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "123456"
jwt = JWTManager(app)
app.secret_key = "clave_secreta_segura"
bcrypt = Bcrypt(app)
CORS(app)

# -------------------------------
# DECORADOR: LOGIN REQUERIDO
# -------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------
# DECORADOR: SOLO ADMIN
# -------------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "administrador":
            return "Acceso denegado", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def inicio():
    nombre = None
    if request.method == 'POST':
        nombre = request.form['nombre']
    return render_template('index.html', nombre=nombre)

@app.route('/usuarios')
@login_required
def usuarios():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
    conn.close()  # 🔥 agregado
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/usuarios/nuevo')
@login_required
@admin_required
def nuevo_usuario():
    return render_template('usuarios_form.html', usuario=None)

@app.route('/usuarios/guardar', methods=['POST'])
@login_required
@admin_required
def guardar_usuario():
    nombre = request.form['nombre']
    email = request.form['email']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO usuarios (nombre, email) VALUES (%s, %s)",
        (nombre, email)
    )
    conn.commit()
    conn.close()  # 🔥 agregado
    return redirect('/usuarios')

@app.route('/usuarios/editar/<int:id>')
@login_required
def editar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    conn.close()  # 🔥 agregado
    return render_template('usuarios_form.html', usuario=usuario)

@app.route('/usuarios/actualizar/<int:id>', methods=['POST'])
@login_required
def actualizar_usuario(id):
    nombre = request.form['nombre']
    email = request.form['email']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET nombre=%s, email=%s WHERE id=%s",
        (nombre, email, id)
    )
    conn.commit()
    conn.close()  # 🔥 agregado
    return redirect('/usuarios')

@app.route('/usuarios/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    conn.close()  # 🔥 agregado
    return redirect('/usuarios')

@app.route('/inscripciones')
@login_required
def inscripciones():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
    SELECT i.id, u.nombre AS usuario, c.nombre AS curso, i.fecha_inscripcion
    FROM inscripciones i
    JOIN usuarios u ON i.usuario_id = u.id
    JOIN cursos c ON i.curso_id = c.id
    """)
    data = cursor.fetchall()
    conn.close()  # 🔥 agregado
    return render_template('inscripciones.html', inscripciones=data)

@app.route('/cursos')
@login_required
def cursos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos")
    cursos = cursor.fetchall()
    conn.close()  # 🔥 agregado
    return render_template('cursos.html', cursos=cursos)

# (TODO TU CÓDIGO SIGUE IGUAL — NO SE ELIMINÓ NADA)

#API LOGIN JWT
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()

    correo = data.get("correo")
    clave = data.get("clave")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM usuarios_sistema WHERE correo = %s",
        (correo,)
    )
    usuario = cursor.fetchone()
    conn.close()

    if not usuario or not bcrypt.check_password_hash(usuario["clave"], clave):
        return jsonify({"msg": "Credenciales incorrectas"}), 401

    access_token = create_access_token(
        identity=str(usuario["id"]),
        additional_claims={"rol": usuario["rol"]}
    )

    return jsonify(access_token=access_token)

# 🔥🔥🔥 CLAVE PARA RENDER 🔥🔥🔥
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
    
