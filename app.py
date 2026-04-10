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
    nombre = None # Variable inicial vacio
    # Si el formulario fue enviado
    if request.method == 'POST':
        # Capturamos el valor del input llamado "nombre"
        nombre = request.form['nombre']
    # Enviamos la variable a la plantilla
    return render_template('index.html', nombre=nombre)

@app.route('/usuarios')
@login_required
def usuarios():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    # Consultamos todos los usuarios
    cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
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
    return redirect('/usuarios')

@app.route('/usuarios/editar/<int:id>')
@login_required
def editar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
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
    return redirect('/usuarios')

@app.route('/usuarios/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
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
    return render_template('inscripciones.html', inscripciones=data)

@app.route('/cursos')
@login_required
def cursos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos")
    cursos = cursor.fetchall()
    return render_template('cursos.html', cursos=cursos)

@app.route('/cursos/nuevo')
@login_required
@admin_required
def nuevo_curso():
    return render_template('cursos_form.html', curso=None)

@app.route('/cursos/guardar', methods=['POST'])
@login_required
@admin_required
def guardar_curso():
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cursos (nombre, descripcion) VALUES (%s, %s)",
        (nombre, descripcion)
    )
    conn.commit()
    return redirect('/cursos')

@app.route('/cursos/editar/<int:id>')
@login_required
@admin_required
def editar_curso(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos WHERE id = %s", (id,))
    curso = cursor.fetchone()
    return render_template('cursos_form.html', curso=curso)

@app.route('/cursos/actualizar/<int:id>', methods=['POST'])
@login_required
@admin_required
def actualizar_curso(id):
    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cursos SET nombre=%s, descripcion=%s WHERE id=%s",
        (nombre, descripcion, id)
    )
    conn.commit()
    return redirect('/cursos')

@app.route('/cursos/eliminar/<int:id>')
@login_required
@admin_required
def eliminar_curso(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cursos WHERE id = %s", (id,))
    conn.commit()
    return redirect('/cursos')

@app.route('/inscripciones/nueva/<int:id>')
@login_required
def nueva_inscripcion(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    usuarios = cursor.fetchone()
    cursor.execute("SELECT * FROM cursos")
    cursos = cursor.fetchall()
    return render_template('inscripciones_form.html', usuarios=usuarios, cursos=cursos)

@app.route('/inscripciones/guardar', methods=['POST'])
@login_required
def guardar_inscripcion():
    usuario_id = request.form['usuario_id']
    curso_id = request.form['curso_id']
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO inscripciones (usuario_id, curso_id, fecha_inscripcion) VALUES (%s, %s, NOW())",
        (usuario_id, curso_id)
    )
    conn.commit()
    return redirect('/inscripciones')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form["correo"]
        clave = request.form["clave"]
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
        "SELECT * FROM usuarios_sistema WHERE correo = %s",
        (correo,)
        )
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

@app.route("/sistema/usuarios/nuevo", methods=["GET", "POST"])
@login_required
@admin_required
def usuarios_sistema_nuevo():
    if request.method == "POST":
        correo = request.form["correo"]
        nombres = request.form["nombres"]
        apellidos = request.form["apellidos"]
        rol = request.form["rol"]
        clave_hash = bcrypt.generate_password_hash("123456").decode("utf-8")
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO usuarios_sistema
        (correo, nombres, apellidos, clave, rol)
        VALUES (%s, %s, %s, %s, %s)
        """, (correo, nombres, apellidos, clave_hash, rol))
        conn.commit()
        conn.close()
        return redirect(url_for("usuarios"))
    return render_template("usuarios_sistema_form.html")

@app.route("/cambiar_clave", methods=["GET", "POST"])
@login_required
def cambiar_clave():
    if request.method == "POST":
        nueva = request.form["nueva"]
        clave_hash = bcrypt.generate_password_hash(nueva).decode("utf-8")
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
        UPDATE usuarios_sistema
        SET clave = %s
        WHERE id = %s
        """, (clave_hash, session["usuario_id"]))
        conn.commit()
        conn.close()
        return redirect(url_for("usuarios"))
    return render_template("cambiar_clave.html")

# -------------------------------
# INSCRIBIR ALUMNO EN CURSO
# (ADMIN Y ASISTENTE)
# -------------------------------
@app.route("/inscripciones/nueva", methods=["GET", "POST"])
@login_required
def inscripcion_nueva():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    # Obtener alumnos
    cursor.execute("SELECT id, nombre FROM usuarios")
    alumnos = cursor.fetchall()
    # Obtener cursos
    cursor.execute("SELECT id, nombre FROM cursos")
    cursos = cursor.fetchall()
    # Si el formulario fue enviado
    if request.method == "POST":
        alumno_id = request.form["alumno_id"]
        curso_id = request.form["curso_id"]
        cursor.execute("""
        INSERT INTO inscripciones (usuario_id, curso_id)
        VALUES (%s, %s)
        """, (alumno_id, curso_id))
        conn.commit()
        conn.close()
        return redirect(url_for("inscripciones"))
    conn.close()
    return render_template(
        "inscripcion_form.html",
        alumnos=alumnos,
        cursos=cursos
    )

#API REST – USUARIOS (CRUD BÁSICO)
@app.route("/api/usuarios", methods=["GET"])
def api_listar_usuarios():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios")
    data = cursor.fetchall()
    conn.close()

    return jsonify({
        "status": "ok",
        "data": data
    })

@app.route("/api/usuarios/<int:id>", methods=["GET"])
def api_obtener_usuario(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    conn.close()

    if usuario is None:
        return jsonify({
            "status": "error",
            "message": "Usuario no encontrado"
        }), 404

    return jsonify({
        "status": "ok",
        "data": usuario
    })

@app.route("/api/usuarios", methods=["POST"])
@jwt_required()
def api_crear_usuario():
    data = request.get_json()

    nombre = data.get("nombre")
    email = data.get("email")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO usuarios (nombre, email) VALUES (%s, %s)",(nombre, email))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Usuario creado correctamente"
    }), 201

@app.route("/api/usuarios/<int:id>", methods=["PUT"])
@jwt_required()
def api_actualizar_usuario(id):
    data = request.get_json()

    nombre = data.get("nombre")
    email = data.get("email")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET nombre=%s, email=%s WHERE id=%s",
        (nombre, email, id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Usuario actualizado correctamente"
    })

@app.route("/api/usuarios/<int:id>", methods=["DELETE"])
@jwt_required()
def api_eliminar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Usuario eliminado"
    })

#API REST – CURSOS (CRUD BÁSICO)

@app.route("/api/cursos", methods=["GET"])
def api_listar_cursos():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos")
    data = cursor.fetchall()
    conn.close()

    return jsonify({
        "status": "ok",
        "data": data
    })

@app.route("/api/cursos/<int:id>", methods=["GET"])
def api_obtener_curso(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cursos WHERE id = %s", (id,))
    curso = cursor.fetchone()
    conn.close()

    if curso is None:
        return jsonify({
            "status": "error",
            "message": "Curso no encontrado"
        }), 404

    return jsonify({
        "status": "ok",
        "data": curso
    })

@app.route("/api/cursos", methods=["POST"])
@jwt_required()
def api_crear_curso():

    claims = get_jwt()
    if claims["rol"] != "administrador":
        return jsonify({
            "status": "error",
            "message": "Solo el administrador puede crear cursos"
        }), 403
    data = request.get_json()

    nombre = data.get("nombre")
    descripcion = data.get("descripcion")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO cursos (nombre, descripcion) VALUES (%s, %s)",
        (nombre, descripcion)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Curso creado correctamente"
    }), 201

@app.route("/api/cursos/<int:id>", methods=["PUT"])
@jwt_required()
def api_actualizar_curso(id):

    claims = get_jwt()
    if claims["rol"] != "administrador":
        return jsonify({
            "status": "error",
            "message": "Solo el administrador puede crear cursos"
        }), 403
    data = request.get_json()

    nombre = data.get("nombre")
    descripcion = data.get("descripcion")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cursos SET nombre=%s, descripcion=%s WHERE id=%s",
        (nombre, descripcion, id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Curso actualizado correctamente"
    })

@app.route("/api/cursos/<int:id>", methods=["DELETE"])
@jwt_required()
def api_eliminar_curso(id):

    claims = get_jwt()
    if claims["rol"] != "administrador":
        return jsonify({
            "status": "error",
            "message": "Solo el administrador puede crear cursos"
        }), 403

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cursos WHERE id = %s", (id,))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Curso eliminado correctamente"
    })

#API REST – INSCRIPCIONES (CRUD BÁSICO)

@app.route("/api/inscripciones", methods=["GET"])
def api_listar_inscripciones():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id,
               u.nombre AS usuario,
               c.nombre AS curso,
               i.fecha_inscripcion
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos c ON i.curso_id = c.id
    """)
    data = cursor.fetchall()
    conn.close()

    return jsonify({
        "status": "ok",
        "data": data
    })

@app.route("/api/inscripciones/<int:id>", methods=["GET"])
def api_obtener_inscripcion(id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.id,
               u.nombre AS usuario,
               c.nombre AS curso,
               i.fecha_inscripcion
        FROM inscripciones i
        JOIN usuarios u ON i.usuario_id = u.id
        JOIN cursos c ON i.curso_id = c.id
        WHERE i.id = %s
    """, (id,))
    inscripcion = cursor.fetchone()
    conn.close()

    if inscripcion is None:
        return jsonify({
            "status": "error",
            "message": "Inscripción no encontrada"
        }), 404

    return jsonify({
        "status": "ok",
        "data": inscripcion
    })

@app.route("/api/inscripciones", methods=["POST"])
@jwt_required()
def api_crear_inscripcion():



    data = request.get_json()

    usuario_id = data.get("usuario_id")
    curso_id = data.get("curso_id")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO inscripciones (usuario_id, curso_id) VALUES (%s, %s)",
        (usuario_id, curso_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Inscripción creada correctamente"
    }), 201

@app.route("/api/inscripciones/<int:id>", methods=["DELETE"])
@jwt_required()
def api_eliminar_inscripcion(id):

    claims = get_jwt()
    if claims["rol"] != "administrador":
        return jsonify({
            "status": "error",
            "message": "Solo el administrador puede crear cursos"
        }), 403

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inscripciones WHERE id = %s", (id,))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Inscripción eliminada"
    })

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

# @app.route("/api/login", methods=["POST"])
# def api_login():
#     data = request.get_json()
#     correo = data.get("correo")
#     clave = data.get("clave")

#     conn = get_connection()
#     cursor = conn.cursor(dictionary=True)
#     cursor.execute("SELECT * FROM usuarios_sistema WHERE correo = %s", (correo,))
#     usuario = cursor.fetchone()
#     conn.close()

#     if not usuario or not bcrypt.check_password_hash(usuario["clave"], clave):
#         return jsonify({"msg": "Credenciales incorrectas"}), 401

#     # Guardamos ID como identity y rol en additional_claims
#     access_token = create_access_token(
#         identity=str(usuario["id"]),
#         additional_claims={"rol": usuario["rol"]}
#     )

#     return jsonify(access_token=access_token)

# from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt

# @jwt_required()
# def ruta_protegida():
#     user_id = int(get_jwt_identity())
#     claims = get_jwt()
#     rol = claims["rol"]
#     return jsonify(user_id=user_id, rol=rol)


if __name__ == '__main__':
    # Inicia el servidor de desarrollo
    # debug=True permite ver errores detallados
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
    
