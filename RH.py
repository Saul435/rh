from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import re
import time
import sqlite3


RH = Flask(__name__)
RH.secret_key = "mi_clave_super_segura_123"
DB = "database.db"

def conectar():
    conn = sqlite3.connect(DB, check_same_thread=False, timeout=3)
    conn.row_factory = sqlite3.Row
    return conn
# ==========================
# FUNCIONES DE BASE DE DATOS
# ==========================
def inicializar_bd():
    #Crea la base de datos y tablas si no existen.
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Crear tabla de ejemplo
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS Usuarios(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT DEFAULT 'invitado',
        estado_aprobacion TEXT DEFAULT 'pendiente',
        estado_perfil TEXT DEFAULT 'incompleto'
    );

    CREATE TABLE IF NOT EXISTS Empleados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cedula TEXT UNIQUE NOT NULL,
        nombre TEXT NOT NULL,
        usuario_id INTEGER,
        fecha_nacimiento TEXT,
        direccion TEXT,
        telefono TEXT,
        correo TEXT,
        departamento TEXT,
        puesto TEXT,
        fecha_ingreso TEXT,
        salario_base REAL,
        estado TEXT DEFAULT 'Activo'
    );
                         
                         
    CREATE TABLE IF NOT EXISTS Nomina (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        empleado_id INTEGER NOT NULL,
        fecha_pago TEXT NOT NULL,
        salario_bruto REAL NOT NULL,
        deducciones REAL DEFAULT 0,
        beneficios REAL DEFAULT 0,
        salario_neto REAL NOT NULL,
        comprobante TEXT,
        FOREIGN KEY (empleado_id) REFERENCES Empleados(id)
    );                             

    CREATE TABLE IF NOT EXISTS Evaluaciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        empleado_id INTEGER NOT NULL,
        fecha TEXT NOT NULL,
        criterio TEXT NOT NULL,
        puntaje INTEGER CHECK(puntaje BETWEEN 1 AND 100),
        resultado TEXT,
        observaciones TEXT,
        FOREIGN KEY (empleado_id) REFERENCES Empleados(id)
    );

    CREATE TABLE IF NOT EXISTS Capacitaciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        curso TEXT NOT NULL,
        descripcion TEXT,
        fecha_inicio TEXT,
        fecha_fin TEXT,
        impacto TEXT,
        asistencias INTEGER DEFAULT 0,
        empleado_id INTEGER,
        FOREIGN KEY (empleado_id) REFERENCES Empleados(id)
    );

    CREATE TABLE IF NOT EXISTS Candidatos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Cedula TEXT UNIQUE ,
        Nombre TEXT,
        PuestoAspira TEXT,
        Departamento TEXT,
        SalarioAspira REAL,
        PCompetencia TEXT,
        PCapacitacion TEXT,
        ExperenciaLaboral TEXT,
        RecomendadoX TEXT
    );

    CREATE TABLE IF NOT EXISTS Competencias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        descripcion TEXT NOT NULL,
        estado TEXT DEFAULT 'Activo'
    );
    
     
    """)
    cursor.execute("SELECT * FROM Usuarios WHERE usuario='admin'")
    if not cursor.fetchone():
        hashed_admin = generate_password_hash("admin")
        cursor.execute("INSERT INTO Usuarios (usuario, password, rol) VALUES (?, ?, ?)", ("admin", hashed_admin, "admin"))

    cursor.execute("""
        UPDATE Usuarios 
        SET estado_aprobacion='aprobado', estado_perfil='completo'
        WHERE rol='admin';
    """)
    conn.commit()
    conn.close()

def configurar_sqlite():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")  # espera hasta 5 segundos antes de fallar
    conn.close()

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "usuario" not in session:
                return redirect(url_for("login"))
            rol = session.get("rol", "invitado")
            if rol not in allowed_roles:
                flash("No tienes permisos para acceder a esta página.", "error")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated
    return decorator

def query_db(query, params=(), fetch=False, retries=2, delay=0.1):
    """
    Ejecuta consultas SQL de forma segura con reintentos automáticos.
    Retorna:
      - Lista de filas si fetch=True
      - True si fue exitoso (INSERT, UPDATE, DELETE)
      - False si ocurrió un error
    """
    for intento in range(retries):
        conn = None
        try:
            conn = sqlite3.connect(DB, check_same_thread=False, timeout=3)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(query, params)

            if fetch:
                data = cur.fetchall()
                conn.close()
                return data

            conn.commit()
            conn.close()
            return True

        except sqlite3.IntegrityError as e:
            if conn: conn.close()
            flash(" Ya existe un registro con esos datos únicos (usuario o cédula).", "error")
            print(f"[INTEGRITY ERROR] {e}")
            return False

        except sqlite3.OperationalError as e:
            if conn: conn.close()
            if "database is locked" in str(e).lower():
                time.sleep(delay)
                continue
            else:
                flash(" Error al acceder a la base de datos.", "error")
                print(f"[SQL ERROR] {e}")
                return False

        except Exception as e:
            if conn: conn.close()
            flash(" Error inesperado en la base de datos.", "error")
            print(f"[ERROR GENERAL] {e}")
            return False

    flash(" La base de datos está ocupada. Intenta nuevamente.", "error")
    return False


# ============
# LOGIN 
# ============

@RH.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        password = request.form.get("password")

        data = query_db("SELECT id, password, rol, estado_aprobacion, estado_perfil FROM Usuarios WHERE usuario=?", (usuario,), fetch=True)
        if not data:
            return render_template("login.html", error="Credenciales incorrectas.")
        row = data[0]

        if not check_password_hash(row["password"], password):
            return render_template("login.html", error="Credenciales incorrectas.")

        # Si rol empleado/supervisor y todavía pendiente de aprobación
        if row["rol"] in ("empleado", "supervisor"):
            if row["estado_aprobacion"] == "pendiente":
                return render_template("login.html", error="Tu cuenta está pendiente de aprobación por un administrador.")
            if row["estado_aprobacion"] == "rechazado":
                return render_template("login.html", error="Tu cuenta fue rechazada por el administrador.")

        # Si perfil incompleto, redirigir a completar_perfil
        if row["estado_perfil"] != "completo":
            # Guardamos usuario en session temporal para que completar_perfil lo tome si fuese necesario
            session["usuario"] = usuario
            session["usuario_id"] = row["id"]
            session["rol"] = row["rol"]
            flash("Por favor completa tu perfil antes de continuar.", "error")
            return redirect(url_for("completar_perfil"))

        # todo ok: crear session y redirigir
        session["usuario"] = usuario
        session["usuario_id"] = row["id"]
        session["rol"] = row["rol"] or "invitado"
        return redirect(url_for("index"))
    return render_template("login.html")




@RH.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "").strip()
        rol = request.form.get("rol", "invitado")

        if not usuario or not password:
            return render_template("register.html", error="Por favor completa todos los campos.")

        # Verificar si ya existe en la BD (para evitar conflicto si alguien ya fue creado manualmente)
        exists = query_db("SELECT id FROM Usuarios WHERE usuario = ?", (usuario,), fetch=True)
        if exists:
            return render_template("register.html", error="El usuario ya existe. Si es tu caso, intenta iniciar sesión o usa recuperar contraseña.")

        # Guardar temporalmente en session (NO insertamos en la BD aún)
        session["registrando"] = {
            "usuario": usuario,
            "password_hash": generate_password_hash(password),
            "rol": rol
        }

        # Si el rol requiere completar perfil, redirigir para completar
        if rol in ("empleado", "supervisor"):
            return redirect(url_for("completar_perfil"))

        # Si es admin u otro rol que NO requiere perfil, insertamos directamente como aprobado
        query_db("""
            INSERT INTO Usuarios (usuario, password, rol, estado_aprobacion, estado_perfil)
            VALUES (?, ?, ?, 'aprobado', 'completo')
        """, (usuario, session["registrando"]["password_hash"], rol))

        session.pop("registrando", None)
        flash("Registro exitoso. Ya puedes iniciar sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")



@RH.route("/completar_perfil", methods=["GET", "POST"])
def completar_perfil():
    # usuario debe haber empezado el registro (tener datos temporales)
    reg = session.get("registrando")
    if not reg and "usuario" not in session:
        flash("No hay registro en proceso. Por favor crea una cuenta primero.", "error")
        return redirect(url_for("register"))

    # Si ya existe sesión activa de usuario aprobado (caso raro), redirigir
    if "usuario" in session and session.get("rol") not in (None, ""):
        # Si ya está logeado y tiene perfil completo, ir al index
        return redirect(url_for("index"))

    if request.method == "POST":
        # Campos del formulario
        cedula = request.form.get("cedula")
        nombre = request.form.get("nombre")
        fecha_nacimiento = request.form.get("fecha_nacimiento")
        direccion = request.form.get("direccion")
        telefono = request.form.get("telefono")
        correo = request.form.get("correo")
        departamento = request.form.get("departamento")
        puesto = request.form.get("puesto")
        fecha_ingreso = request.form.get("fecha_ingreso")
        salario_base = request.form.get("salario_base")
        estado = request.form.get("estado", "Activo")

        # Si no tenemos los datos temporales por algún motivo -> pedir que se registre de nuevo
        if not reg:
            flash("No se encontraron los datos de registro. Por favor regístrate de nuevo.", "error")
            return redirect(url_for("register"))

        # 1) Insertar en Usuarios (ya que ahora completó el perfil)
        # Si el rol es admin, lo marcamos aprobado de inmediato; si no, queda pendiente de aprobación
        estado_aprob = 'aprobado' if reg["rol"] == "admin" else 'pendiente'
        estado_perf = 'completo'

        insert_user_ok = query_db("""
            INSERT INTO Usuarios (usuario, password, rol, estado_aprobacion, estado_perfil)
            VALUES (?, ?, ?, ?, ?)
        """, (reg["usuario"], reg["password_hash"], reg["rol"], estado_aprob, estado_perf))

        if not insert_user_ok:
            flash("Error al crear el usuario. Probablemente el nombre de usuario ya existe.", "error")
            return redirect(url_for("register"))

        # Recuperar id del usuario insertado
        row = query_db("SELECT id FROM Usuarios WHERE usuario = ?", (reg["usuario"],), fetch=True)
        if not row:
            flash("Error interno al crear el usuario.", "error")
            return redirect(url_for("register"))
        usuario_id = row[0]["id"]

        # 2) Insertar en Empleados (si aplica)
        if reg["rol"] in ("empleado", "supervisor"):
            exito_emp = query_db("""
                INSERT INTO Empleados (cedula, nombre, fecha_nacimiento, direccion, telefono, correo,
                    departamento, puesto, fecha_ingreso, salario_base, estado, usuario_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cedula, nombre, fecha_nacimiento, direccion, telefono, correo,
                  departamento, puesto, fecha_ingreso, salario_base, estado, usuario_id))

            if not exito_emp:
                # Si falla crear empleado, borramos el usuario recién creado para no dejar inconsistencia
                query_db("DELETE FROM Usuarios WHERE id = ?", (usuario_id,))
                flash("Error al guardar datos del perfil. Intenta de nuevo.", "error")
                return redirect(url_for("completar_perfil"))

        # Limpiar sesión temporal
        session.pop("registrando", None)

        # Si el usuario requiere aprobación del admin
        if estado_aprob == 'pendiente':
            flash("Tu perfil fue completado. Ahora está pendiente de aprobación del administrador.", "success")
            # opcional: cerrar la sesión para que no puedan navegar
            return redirect(url_for("login"))
        else:
            # aprobado (admin), creamos sesión y redirigimos
            session["usuario"] = reg["usuario"]
            session["usuario_id"] = usuario_id
            session["rol"] = reg["rol"]
            flash("Perfil completado y cuenta activa.", "success")
            return redirect(url_for("index"))

    # GET -> mostrar formulario; prefill con session["registrando"] si quieres
    datos_prefill = {
        "usuario": reg["usuario"],
        "rol": reg["rol"]
    } if reg else {}

    return render_template("completar_perfil.html", usuario=datos_prefill.get("usuario"), rol=datos_prefill.get("rol"))


@RH.route("/cancelar_registro")
def cancelar_registro():
    # Limpiar datos de session temporal
    session.pop("registrando", None)
    # opcional: si hay usuario_id temporal en session y existe en DB y está pendiente, borrarlo
    uid = session.get("usuario_id")
    if uid:
        row = query_db("SELECT estado_aprobacion FROM Usuarios WHERE id = ?", (uid,), fetch=True)
        if row and row[0]["estado_aprobacion"] == "pendiente":
            query_db("DELETE FROM Usuarios WHERE id = ?", (uid,))
    session.pop("usuario_id", None)
    session.pop("usuario", None)
    session.pop("rol", None)
    flash("Registro cancelado.", "info")
    return redirect(url_for("register"))


@RH.route("/logout")
def logout():
    session.pop("usuario", None)
    return redirect(url_for("login"))

#=======
#HOMEEEE
#=======

@RH.route("/")
def index():
    if "usuario" not in session:
        return redirect(url_for("login"))

    # Si es empleado/supervisor y no completó perfil → redirigir
    if session.get("rol") in ("empleado", "supervisor"):
        emp = query_db("SELECT id FROM Empleados WHERE usuario_id = ?", (session["usuario_id"],), fetch=True)
        if not emp:
            flash("Debes completar tu perfil antes de usar el sistema.", "error")
            return redirect(url_for("completar_perfil"))

    return render_template("index.html", usuario=session["usuario"])


@RH.route("/dashboard")
def dashboard_empleado():
    if "usuario" not in session:
        return redirect(url_for("login"))
    if session.get("rol") != "empleado":
        flash("Acceso restringido al dashboard de empleados.", "error")
        return redirect(url_for("index"))

    user_id = session.get("usuario_id")
    emp_rows = query_db("SELECT * FROM Empleados WHERE usuario_id = ?", (user_id,), fetch=True)
    if not emp_rows:
        flash("Completa tu perfil para acceder al dashboard.", "error")
        return redirect(url_for("completar_perfil"))

    emp = emp_rows[0]

    # Evaluaciones propias
    evaluaciones = query_db("SELECT * FROM Evaluaciones WHERE empleado_id = ? ORDER BY fecha DESC", (emp["id"],), fetch=True) or []

    # Indicadores generales (ejemplos):
    total_empleados = query_db("SELECT COUNT(*) as c FROM Empleados", fetch=True)[0][0]
    cursos_disponibles = query_db("SELECT COUNT(*) as c FROM Capacitaciones", fetch=True)[0][0]
    promedio_puntaje = None
    row = query_db("SELECT AVG(puntaje) as avg FROM Evaluaciones WHERE empleado_id = ?", (emp["id"],), fetch=True)
    if row and row[0]["avg"] is not None:
        promedio_puntaje = round(row[0]["avg"], 2)

    return render_template("dashboard.html",
                           empleado=emp,
                           evaluaciones=evaluaciones,
                           total_empleados=total_empleados,
                           cursos_disponibles=cursos_disponibles,
                           promedio_puntaje=promedio_puntaje)

# ==================================
# SECCIÓN DE EMPLEADOS
# ==================================



@RH.route("/empleados")
def empleados():
    if "usuario" not in session:
        return redirect(url_for("login"))
    data = query_db("SELECT * FROM Empleados ORDER BY id DESC", fetch=True)
    return render_template("empleados.html", empleados=data, editar=None)

def normalizar_usuario(nombre):
    # quitar tildes/acentos puede requerir biblioteca; por ahora simplificamos:
    usuario = nombre.strip().lower()
    # reemplazar espacios y no alfanuméricos por guiones bajos
    usuario = re.sub(r'[^a-z0-9]+', '_', usuario)
    usuario = usuario.strip('_')
    return usuario or "user"

@RH.route("/empleados/agregar", methods=["POST"])
@role_required(["admin", "supervisor"])
def agregar_empleado():
    if "usuario" not in session:
        return redirect(url_for("login"))

    cedula = request.form.get("cedula")
    nombre = request.form.get("nombre")
    fecha_nacimiento = request.form.get("fecha_nacimiento")
    direccion = request.form.get("direccion")
    telefono = request.form.get("telefono")
    correo = request.form.get("correo")
    departamento = request.form.get("departamento")
    puesto = request.form.get("puesto")
    fecha_ingreso = request.form.get("fecha_ingreso")
    salario_base = request.form.get("salario_base")
    estado = request.form.get("estado")

    # Insert empleado (sin usuario_id aún)
    exito = query_db("""
        INSERT INTO Empleados (cedula, nombre, fecha_nacimiento, direccion, telefono, correo,
             departamento, puesto, fecha_ingreso, salario_base, estado)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (cedula, nombre, fecha_nacimiento, direccion, telefono, correo,
          departamento, puesto, fecha_ingreso, salario_base, estado))

    if not exito:
        # mensaje de error ya manejado en query_db
        data = query_db("SELECT * FROM Empleados ORDER BY id DESC", fetch=True)
        return render_template("empleados.html", empleados=data, editar=None)

    # Obtener el id del empleado recién insertado
    conn = conectar()
    cur = conn.cursor()
    cur.execute("SELECT id FROM Empleados WHERE cedula = ?", (cedula,))
    row = cur.fetchone()
    emp_id = row["id"] if row else None

    # Crear usuario asociado: username basado en nombre
    base_user = normalizar_usuario(nombre)
    user_candidate = base_user
    suffix = 1
    # verificar unicidad
    while True:
        exists = query_db("SELECT id FROM Usuarios WHERE usuario = ?", (user_candidate,), fetch=True)
        if not exists:
            break
        suffix += 1
        user_candidate = f"{base_user}_{suffix}"

    hashed_pw = generate_password_hash(str(cedula))
    # insertar usuario
    query_db("INSERT INTO Usuarios (usuario, password, rol) VALUES (?, ?, ?)", (user_candidate, hashed_pw, "empleado"))

    # recuperar id del usuario insertado
    cur.execute("SELECT id FROM Usuarios WHERE usuario = ?", (user_candidate,))
    urow = cur.fetchone()
    usuario_id = urow["id"] if urow else None

    # actualizar empleado con usuario_id
    if usuario_id and emp_id:
        cur.execute("UPDATE Empleados SET usuario_id = ? WHERE id = ?", (usuario_id, emp_id))
        conn.commit()

    conn.close()
    flash(f" Empleado agregado. Usuario creado: {user_candidate}", "success")
    data = query_db("SELECT * FROM Empleados ORDER BY id DESC", fetch=True)
    return render_template("empleados.html", empleados=data, editar=None)



@RH.route("/empleados/eliminar/<int:id>")
@role_required(["admin"])
def eliminar_empleado(id):
    if "usuario" not in session:
        return redirect(url_for("login"))
    query_db("DELETE FROM Empleados WHERE id = ?", (id,))
    return redirect(url_for("empleados"))

@RH.route("/empleados/editar/<int:id>", methods=["GET", "POST"])
@role_required(["admin"])
def editar_empleado(id):
    if "usuario" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        datos = (
            request.form.get("cedula"),
            request.form.get("nombre"),
            request.form.get("fecha_nacimiento"),
            request.form.get("direccion"),
            request.form.get("telefono"),
            request.form.get("correo"),
            request.form.get("departamento"),
            request.form.get("puesto"),
            request.form.get("fecha_ingreso"),
            request.form.get("salario_base"),
            request.form.get("estado"),
            id
        )
        query_db("""
            UPDATE Empleados SET
                cedula=?, nombre=?, fecha_nacimiento=?, direccion=?, telefono=?, correo=?,
                departamento=?, puesto=?, fecha_ingreso=?, salario_base=?, estado=?
            WHERE id=?
        """, datos)
        return redirect(url_for("empleados"))

    emp = query_db("SELECT * FROM Empleados WHERE id=?", (id,), fetch=True)
    if not emp:
        return redirect(url_for("empleados"))

    data = query_db("SELECT * FROM Empleados ORDER BY id DESC", fetch=True)
    return render_template("empleados.html", empleados=data, editar=emp[0])


# ==========================
# CAPACITACIONES
# ==========================

@RH.route("/capacitaciones")
def capacitaciones():
    if "usuario" not in session:
        return redirect(url_for("login"))
    
    sql = """
        SELECT c.id, c.curso, c.descripcion, c.fecha_inicio, c.fecha_fin,
               c.impacto, c.asistencias,
               e.nombre AS empleado_nombre, e.cedula AS empleado_cedula
        FROM Capacitaciones c
        LEFT JOIN Empleados e ON c.empleado_id = e.id
        ORDER BY c.id DESC
    """
    data = query_db(sql, fetch=True) or []
    return render_template("capacitaciones.html", capacitaciones=data)

@RH.route("/capacitaciones/agregar", methods=["POST"])
@role_required(["admin", "supervisor"])
def agregar_capacitacion():
    if "usuario" not in session:
        return redirect(url_for("login"))

    curso = request.form.get("curso", "").strip()
    if not curso:
        flash("⚠️ Debes indicar el nombre del curso.", "error")
        return redirect(url_for("capacitaciones"))

    descripcion = request.form.get("descripcion", "").strip() or None
    fecha_inicio = request.form.get("fecha_inicio", "").strip() or None
    fecha_fin = request.form.get("fecha_fin", "").strip() or None
    impacto = request.form.get("impacto", "").strip() or None
    empleado_id = request.form.get("empleado_id", "").strip() or None
    empleado_input = request.form.get("empleado_input", "").strip() or None

    # Buscar empleado si solo se escribió cédula o nombre
    if not empleado_id and empleado_input:
        row = query_db("SELECT id FROM Empleados WHERE cedula = ? COLLATE NOCASE", (empleado_input,), fetch=True)
        if not row:
            row = query_db("SELECT id FROM Empleados WHERE nombre = ? COLLATE NOCASE", (empleado_input,), fetch=True)
        if row:
            empleado_id = row[0]["id"]

    query_db("""
        INSERT INTO Capacitaciones (curso, descripcion, fecha_inicio, fecha_fin, impacto, asistencias, empleado_id)
        VALUES (?, ?, ?, ?, ?, 0, ?)
    """, (curso, descripcion, fecha_inicio, fecha_fin, impacto, empleado_id if empleado_id else None))

    flash("✅ Capacitación registrada correctamente.", "success")
    return redirect(url_for("capacitaciones"))

@RH.route("/capacitaciones/eliminar/<int:id>")
@role_required(["admin"])
def eliminar_capacitacion(id):
    if "usuario" not in session:
        return redirect(url_for("login"))
    query_db("DELETE FROM Capacitaciones WHERE id = ?", (id,))
    flash("🗑️ Capacitación eliminada correctamente.", "success")
    return redirect(url_for("capacitaciones"))

# ----------------------------------------
# Sumar asistencia capacitaciones
# ----------------------------------------
@RH.route("/capacitaciones/asistencia/<int:id>", methods=["POST"])
@role_required(["admin","supervisor"])
def sumar_asistencia(id):
    if "usuario" not in session:
        return jsonify({"ok": False, "msg": "No autorizado"}), 401
    try:
        conn = conectar()
        cur = conn.cursor()
        cur.execute("SELECT asistencias FROM Capacitaciones WHERE id = ?", (id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return jsonify({"ok": False, "msg": "No encontrada"}), 404
        nuevas = (row["asistencias"] or 0) + 1
        cur.execute("UPDATE Capacitaciones SET asistencias = ? WHERE id = ?", (nuevas, id))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "asistencias": nuevas})
    except Exception as e:
        print("[ERROR asistencia]", e)
        return jsonify({"ok": False, "msg": "Error interno"}), 500

# ----------------------------------------
# Buscar empleados (autocomplete) capacitacion
# ----------------------------------------
@RH.route("/empleados/search")
def empleados_search():
    if "usuario" not in session:
        return jsonify([]), 401
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])

    q_like = f"%{q}%"
    rows = query_db("""
        SELECT id, cedula, nombre
        FROM Empleados
        WHERE cedula LIKE ? OR nombre LIKE ?
        ORDER BY nombre LIMIT 10
    """, (q_like, q_like), fetch=True) or []

    return jsonify([
        {"id": r["id"], "cedula": r["cedula"], "nombre": r["nombre"]}
        for r in rows
    ])

# ==========================
# EVALUACIONES DE DESEMPEÑO
# ==========================

@RH.route("/evaluaciones")
def evaluaciones():
    if "usuario" not in session:
        return redirect(url_for("login"))
    sql = """
        SELECT ev.id, ev.fecha, ev.criterio, ev.puntaje, ev.resultado, ev.observaciones,
               e.nombre
        FROM Evaluaciones ev
        LEFT JOIN Empleados e ON ev.empleado_id = e.id
        ORDER BY ev.fecha DESC
    """
    data = query_db(sql, fetch=True) or []
    return render_template("evaluaciones.html", evaluaciones=data)

@RH.route("/evaluaciones/agregar", methods=["POST"])
@role_required(["admin", "supervisor"])
def agregar_evaluacion():
    if "usuario" not in session:
        return redirect(url_for("login"))
    empleado_id = request.form.get("empleado_id")
    empleado_input = request.form.get("empleado_input", "").strip()
    fecha = request.form.get("fecha")
    criterio = request.form.get("criterio")
    puntaje = request.form.get("puntaje")
    resultado = request.form.get("resultado")
    observaciones = request.form.get("observaciones")

    # Buscar empleado por nombre o cédula si no hay ID
    if not empleado_id and empleado_input:
        row = query_db("SELECT id FROM Empleados WHERE cedula=? COLLATE NOCASE", (empleado_input,), fetch=True)
        if not row:
            row = query_db("SELECT id FROM Empleados WHERE nombre=? COLLATE NOCASE", (empleado_input,), fetch=True)
        if row:
            empleado_id = row[0]["id"]

    query_db("""
        INSERT INTO Evaluaciones (empleado_id, fecha, criterio, puntaje, resultado, observaciones)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (empleado_id, fecha, criterio, puntaje, resultado, observaciones))

    flash("✅ Evaluación registrada correctamente.", "success")
    return redirect(url_for("evaluaciones"))

@RH.route("/evaluaciones/eliminar/<int:id>")
@role_required(["admin"])
def eliminar_evaluacion(id):
    if "usuario" not in session:
        return redirect(url_for("login"))
    query_db("DELETE FROM Evaluaciones WHERE id=?", (id,))
    flash("🗑️ Evaluación eliminada correctamente.", "success")
    return redirect(url_for("evaluaciones"))

# ==========================
# GESTION DE NOMINA
# ==========================

# ==========================
# NÓMINA
# ==========================
@RH.route("/nomina")
@role_required(["admin", "supervisor"])
def nomina():
    sql = """
        SELECT n.id, n.fecha_pago, n.salario_bruto, n.deducciones, n.beneficios, 
               n.salario_neto, n.comprobante,
               e.nombre AS empleado_nombre, e.cedula AS empleado_cedula
        FROM Nomina n
        LEFT JOIN Empleados e ON n.empleado_id = e.id
        ORDER BY n.id DESC
    """
    data = query_db(sql, fetch=True) or []
    empleados = query_db("SELECT id, nombre, cedula, salario_base FROM Empleados ORDER BY nombre", fetch=True) or []
    return render_template("nomina.html", nominas=data, empleados=empleados)


@RH.route("/nomina/agregar", methods=["POST"])
@role_required(["admin", "supervisor"])
def agregar_nomina():
    if "usuario" not in session:
        return redirect(url_for("login"))

    empleado_id = request.form.get("empleado_id")
    try:
        salario_bruto = float(request.form.get("salario_bruto") or 0)
        deducciones = float(request.form.get("deducciones") or 0)
        beneficios = float(request.form.get("beneficios") or 0)
    except ValueError:
        flash("Valores numéricos inválidos.", "error")
        return redirect(url_for("nomina"))

    fecha_pago = request.form.get("fecha_pago") or None
    salario_neto = salario_bruto - deducciones + beneficios

    success = query_db("""
        INSERT INTO Nomina (empleado_id, fecha_pago, salario_bruto, deducciones, beneficios, salario_neto)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (empleado_id, fecha_pago, salario_bruto, deducciones, beneficios, salario_neto))

    if not success:
        flash("Error al guardar la nómina.", "error")
    else:
        flash("💰 Nómina generada exitosamente.", "success")
    return redirect(url_for("nomina"))


@RH.route("/nomina/eliminar/<int:id>")
@role_required(["admin"])
def eliminar_nomina(id):
    query_db("DELETE FROM Nomina WHERE id = ?", (id,))
    flash("🗑️ Registro de nómina eliminado.", "success")
    return redirect(url_for("nomina"))


# Generar comprobante (PDF simple — guarda en /static)
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import os

@RH.route("/nomina/comprobante/<int:id>")
@role_required(["admin","supervisor"])
def nomina_comprobante(id):
    row = query_db("""
        SELECT n.*, e.nombre, e.cedula
        FROM Nomina n
        JOIN Empleados e ON n.empleado_id = e.id
        WHERE n.id=?
    """, (id,), fetch=True)

    if not row:
        flash("Comprobante no encontrado.", "error")
        return redirect(url_for("nomina"))
    r = row[0]

    # nombre del archivo en static
    filename = f"comprobante_nomina_{id}.pdf"
    static_path = os.path.join("static", filename)
    # Ruta absoluta si tu app lo requiere, reportlab puede escribirla tal cual
    c = canvas.Canvas(static_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(30, 760, "Comprobante de Nómina")
    c.setFont("Helvetica", 11)
    c.drawString(30, 740, f"Empleado: {r['nombre']} ({r['cedula']})")
    c.drawString(30, 720, f"Fecha de pago: {r['fecha_pago']}")
    c.drawString(30, 700, f"Salario bruto: {r['salario_bruto']}")
    c.drawString(30, 680, f"Deducciones: {r['deducciones']}")
    c.drawString(30, 660, f"Beneficios: {r['beneficios']}")
    c.drawString(30, 640, f"Salario neto: {r['salario_neto']}")
    c.save()

    # Actualizar campo comprobante en DB con la ruta relativa para que el template la use
    query_db("UPDATE Nomina SET comprobante = ? WHERE id = ?", (f"/static/{filename}", id))
    return redirect(f"/static/{filename}")


# API helper: devuelve datos del empleado (para autocompletar)
@RH.route("/empleado/<int:id>")
def obtener_empleado(id):
    row = query_db("SELECT id, nombre, cedula, salario_base, departamento, puesto FROM Empleados WHERE id = ?", (id,), fetch=True)
    if not row:
        return jsonify({"error": "Empleado no encontrado"}), 404
    e = row[0]
    return jsonify({
        "id": e["id"],
        "nombre": e["nombre"],
        "cedula": e["cedula"],
        "salario_base": e["salario_base"],
        "departamento": e["departamento"],
        "puesto": e["puesto"]
    })
#==========================
#SOLICITUDES
#==========================
@RH.route("/solicitudes")
@role_required(["admin"])
def solicitudes():
    if "usuario" not in session:
        return redirect(url_for("login"))

    # Asegúrate de usar fetch=True para obtener filas
    sql = "SELECT id, usuario, rol, estado_aprobacion, estado_perfil FROM Usuarios WHERE estado_aprobacion = 'pendiente' ORDER BY id DESC"
    data = query_db(sql, fetch=True)

    # Si query_db devolvió False por algún error, evita pasar un bool a la plantilla
    if not data:
        data = []  # fallback seguro: plantilla verá "no hay solicitudes"

    # opcional: convertir rows a dicts si necesitas .get en template
    solicitudes_list = []
    for r in data:
        solicitudes_list.append({
            "id": r["id"],
            "usuario": r["usuario"],
            "rol": r["rol"],
            "estado_aprobacion": r.get("estado_aprobacion") if isinstance(r, dict) else r["estado_aprobacion"],
            "estado_perfil": r.get("estado_perfil") if isinstance(r, dict) else r["estado_perfil"]
        })

    return render_template("solicitudes.html", solicitudes=solicitudes_list)


@RH.route("/solicitudes/aprobar/<int:id>")
@role_required(["admin"])
def aprobar_solicitud(id):
    query_db("UPDATE Usuarios SET estado_aprobacion='aprobado' WHERE id=?", (id,))
    flash("Usuario aprobado. Ahora puede completar su perfil.", "success")
    return redirect("/solicitudes")

@RH.route("/solicitudes/rechazar/<int:id>")
@role_required(["admin"])
def rechazar_solicitud(id):
    query_db("UPDATE Usuarios SET estado_aprobacion='rechazado' WHERE id=?", (id,))
    flash("Usuario rechazado.", "error")
    return redirect("/solicitudes")



# ==========================
# LÓGICA DEL PROGRAMA
# ==========================
if __name__ == "__main__":
    inicializar_bd()
    configurar_sqlite()
    RH.run(debug=True)
    
