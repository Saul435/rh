from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
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
        rol TEXT DEFAULT 'invitado'
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
            flash("⚠️ Ya existe un registro con esos datos únicos (usuario o cédula).", "error")
            print(f"[INTEGRITY ERROR] {e}")
            return False

        except sqlite3.OperationalError as e:
            if conn: conn.close()
            if "database is locked" in str(e).lower():
                time.sleep(delay)
                continue
            else:
                flash("⚠️ Error al acceder a la base de datos.", "error")
                print(f"[SQL ERROR] {e}")
                return False

        except Exception as e:
            if conn: conn.close()
            flash("⚠️ Error inesperado en la base de datos.", "error")
            print(f"[ERROR GENERAL] {e}")
            return False

    flash("⚠️ La base de datos está ocupada. Intenta nuevamente.", "error")
    return False


# ============
# LOGIN 
# ============

@RH.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario")
        password = request.form.get("password")

        data = query_db("SELECT id, password, rol FROM Usuarios WHERE usuario=?", (usuario,), fetch=True)
        if data and check_password_hash(data[0]["password"], password):
            session["usuario"] = usuario
            session["usuario_id"] = data[0]["id"]
            session["rol"] = data[0]["rol"] or "invitado"

            # redirección según rol: admin -> index (admin), supervisor -> index, empleado -> dashboard
            if session["rol"] == "empleado":
                return redirect(url_for("index"))
            elif session["rol"] == "supervisor":
                return redirect(url_for("index"))
            else:
                return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Credenciales incorrectas.")
    return render_template("login.html")


@RH.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        usuario = request.form.get("usuario").strip()
        password = request.form.get("password").strip()
        rol = request.form.get("rol", "invitado")
        if not usuario or not password:
            return render_template("register.html", error="Por favor completa todos los campos.")
        hashed_pw = generate_password_hash(password)
        success = query_db("INSERT INTO Usuarios (usuario, password, rol) VALUES (?, ?, ?)", (usuario, hashed_pw, rol))
        if not success:
            return render_template("register.html", error="El usuario ya existe.")
        # crear session
        session["usuario"] = usuario
        # buscar id del usuario creado
        row = query_db("SELECT id, rol FROM Usuarios WHERE usuario = ?", (usuario,), fetch=True)
        if row:
            session["usuario_id"] = row[0]["id"]
            session["rol"] = row[0]["rol"]
        # si el rol requiere completar perfil (empleado/supervisor) redirigir
        if rol in ("empleado", "supervisor"):
            return redirect(url_for("completar_perfil"))
        return redirect(url_for("index"))
    return render_template("register.html")

@RH.route("/completar_perfil", methods=["GET", "POST"])
def completar_perfil():
    if "usuario" not in session:
        return redirect(url_for("login"))

    # si ya tiene empleado vinculado, no permitir
    user_row = query_db("SELECT id, rol FROM Usuarios WHERE usuario = ?", (session["usuario"],), fetch=True)
    if not user_row:
        return redirect(url_for("logout"))
    user_id = user_row[0]["id"]
    rol = user_row[0]["rol"]

    # Solo empleados o supervisores necesitan completar
    if rol not in ("empleado", "supervisor"):
        flash("No aplica completar perfil para este rol.", "error")
        return redirect(url_for("index"))

    # POST: crear Empleado y enlazar
    if request.method == "POST":
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

        # insertar empleado con usuario_id = user_id
        exito = query_db("""
            INSERT INTO Empleados (cedula, nombre, fecha_nacimiento, direccion, telefono, correo,
                 departamento, puesto, fecha_ingreso, salario_base, estado, usuario_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cedula, nombre, fecha_nacimiento, direccion, telefono, correo,
              departamento, puesto, fecha_ingreso, salario_base, estado, user_id))

        if not exito:
            return render_template("completar_perfil.html", error="Error al guardar. Verifique los datos.")

        flash("Perfil completado correctamente. Ya puedes usar tu panel.", "success")
        return redirect(url_for("index"))

    # GET: mostrar formulario
    return render_template("completar_perfil.html", usuario=session["usuario"], rol=rol)


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
    return render_template("index.html", usuario=session["usuario"])

@RH.route("/dashboard")
def dashboard_empleado():
    if "usuario" not in session:
        return redirect(url_for("login"))
    # sólo empleados
    if session.get("rol") != "empleado":
        flash("Acceso restringido al dashboard de empleados.", "error")
        return redirect(url_for("index"))

    user_id = session.get("usuario_id")
    # traer empleado vinculado
    emp = query_db("SELECT * FROM Empleados WHERE usuario_id = ?", (user_id,), fetch=True)
    if not emp:
        flash("Completa tu perfil para acceder al dashboard.", "error")
        return redirect(url_for("completar_perfil"))
    emp = emp[0]

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
# LÓGICA DEL PROGRAMA
# ==========================
if __name__ == "__main__":
    inicializar_bd()
    configurar_sqlite()
    RH.run(debug=True)
