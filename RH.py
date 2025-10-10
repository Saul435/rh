from flask import Flask, render_template, request, redirect, url_for

import sqlite3


RH = Flask(__name__)
DB = "database.db"

def conectar():
    return sqlite3.connect(DB)
# ==========================
# FUNCIONES DE BASE DE DATOS
# ==========================
def inicializar_bd():
    #Crea la base de datos y tablas si no existen.
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Crear tabla de ejemplo
    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS Competencias (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Descripcion TEXT NOT NULL,
        Estado TEXT  NOT NULL
    );                             

    CREATE TABLE IF NOT EXISTS Capacitaciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Descripcion TEXT,
        Nivel TEXT,
        FechaDesde TEXT,
        FechaHasta TEXT,
        Salario DOUBLE
    );

    CREATE TABLE IF NOT EXISTS Puestos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Nombre TEXT,
        NivelR TEXT,
        NivelMinSalario TEXT,
        NivelMaxSalario TEXT,
        Estado TEXT
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

    CREATE TABLE IF NOT EXISTS ExpLaboral (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Empresa TEXT ,
        PuestOcupado TEXT ,
        FechaDesde TEXT ,
        FechaHasta TEXT ,
        Salario REAL UNIQUE 
    );

    CREATE TABLE IF NOT EXISTS Empleados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Cedula TEXT UNIQUE,
        Nombre TEXT,
        FechaInt TEXT,
        Departamento  TEXT, 
        Puesto TEXT,
        SalarioMensual REAL,
        Estado TEXT
    );
    """)
    
    conn.commit()
    conn.close()

def query_db(query, params=(), fetch=False):
    conn = conectar()
    cur = conn.cursor()
    cur.execute(query, params)
    if fetch:
        rows = cur.fetchall()
        conn.close()
        return rows
    conn.commit()
    conn.close()
    return None


#=========================================
#PRIMERA SESION DEL PROGRAMA: COMPETENCIAS
#=========================================

@RH.route("/")

def index():
    return render_template("index.html")

@RH.route("/competencias")
def competencias():
    # usar query_db para obtener datos
    data = query_db("SELECT id, Descripcion, Estado FROM Competencias ORDER BY id DESC", fetch=True)
    return render_template("competencias.html", competencias=data or [])

@RH.route("/competencias/agregar", methods=["POST"])
def agregar_competencia():
    desc = request.form.get("descripcion", "").strip()
    estado = request.form.get("estado", "").strip() or "Activo"
    if desc:
        query_db("INSERT INTO Competencias (Descripcion, Estado) VALUES (?, ?)", (desc, estado))
    return redirect(url_for("competencias"))

@RH.route("/competencias/eliminar/<int:id>")
def eliminar_competencia(id):
    query_db("DELETE FROM Competencias WHERE id = ?", (id,))
    return redirect(url_for("competencias"))

#===========================================
#SEGUNDA SESION DEL PROGRAMA: Capacitaciones
#===========================================


@RH.route("/capacitaciones")
def capacitaciones():
    data = query_db("SELECT id, Descripcion, Nivel, FechaDesde, FechaHasta, Salario FROM Capacitaciones ORDER BY id DESC", fetch=True)
    niveles = ["TI", "compras", "Finanzas", "Marketing"]
    return render_template("capacitaciones.html", capacitaciones=data or [], niveles=niveles)

@RH.route("/capacitaciones/agregar", methods=["POST"])
def agregar_capacitacion():
    nombre = request.form.get("nombre", "").strip()
    nivel = request.form.get("nivel", "").strip() or None
    fechad = request.form.get("fecha_desde", "").strip() or None
    fechah = request.form.get("fecha_hasta", "").strip() or None
    Salario = request.form.get("Salario", "").strip() or None
    if nombre:
        query_db("""
            INSERT INTO Capacitaciones (Descripcion, Nivel, FechaDesde, FechaHasta, Salario)
            VALUES (?, ?, ?, ?, ?)
        """, (nombre, nivel, fechad, fechah, Salario))
    return redirect(url_for("capacitaciones"))

@RH.route("/capacitaciones/eliminar/<int:id>")
def eliminar_capacitacion(id):
    query_db("DELETE FROM Capacitaciones WHERE id = ?", (id,))
    return redirect(url_for("capacitaciones"))


# ==========================
# LÓGICA DEL PROGRAMA
# ==========================
if __name__ == "__main__":
    inicializar_bd()
    RH.run(debug=True)