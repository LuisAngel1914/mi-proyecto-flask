from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt,
    get_jwt_identity
)
from functools import wraps
from flask_cors import CORS
import mysql.connector
import os

app = Flask(__name__)

# CONFIGURACIÓN
app.config["JWT_SECRET_KEY"] = "123456"
app.secret_key = "clave_secreta_segura"

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

# -------------------------------
# CONEXIÓN A BD (Railway)
# -------------------------------
def get_connection():
    return mysql.connector.connect(
        host=os.environ.get("MYSQLHOST"),
        user=os.environ.get("MYSQLUSER"),
        password=os.environ.get("MYSQLPASSWORD"),
        database=os.environ.get("MYSQLDATABASE"),
        port=int(os.environ.get("MYSQLPORT", 3306))
    )

# -------------------------------
# DECORADORES
# -------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("rol") != "administrador":
            return "Acceso denegado", 403
        return f(*args, **kwargs)
    return decorated_function

# -------------------------------
# RUTA PARA CREAR BD AUTOMÁTICAMENTE
# -------------------------------
@app.route("/init-db")
def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(100),
        email VARCHAR(100)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cursos (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(100),
        descripcion TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS inscripciones (
        id INT AUTO_INCREMENT PRIMARY KEY,
        usuario_id INT,
        curso_id INT,
        fecha_inscripcion DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios_sistema (
        id INT AUTO_INCREMENT PRIMARY KEY,
        correo VARCHAR(100),
        nombres VARCHAR(100),
        apellidos VARCHAR(100),
        clave VARCHAR(255),
        rol VARCHAR(50)
    )
    """)

    conn.commit()
    conn.close()

    return "Base de datos creada 🚀"

# -------------------------------
# LOGIN
# -------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form["correo"]
        clave = request.form["clave"]

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios_sistema WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()
        conn.close()

        if usuario and bcrypt.check_password_hash(usuario["clave"], clave):
            session["usuario_id"] = usuario["id"]
            session["rol"] = usuario["rol"]
            session["nombre"] = usuario["nombres"]
            return redirect(url_for("usuarios"))

        return "Credenciales incorrectas"

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------------------
# USUARIOS
# -------------------------------
@app.route('/usuarios')
@login_required
def usuarios():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios")
    data = cursor.fetchall()
    conn.close()
    return render_template('usuarios.html', usuarios=data)

# -------------------------------
# API LOGIN JWT
# -------------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()

    correo = data.get("correo")
    clave = data.get("clave")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios_sistema WHERE correo = %s", (correo,))
    usuario = cursor.fetchone()
    conn.close()

    if not usuario or not bcrypt.check_password_hash(usuario["clave"], clave):
        return jsonify({"msg": "Credenciales incorrectas"}), 401

    access_token = create_access_token(
        identity=str(usuario["id"]),
        additional_claims={"rol": usuario["rol"]}
    )

    return jsonify(access_token=access_token)

# -------------------------------
# INICIO
# -------------------------------
@app.route('/')
def inicio():
    return redirect(url_for("login"))

# -------------------------------
# MAIN
# -------------------------------
if __name__ == '__main__':
    app.run(debug=True)
