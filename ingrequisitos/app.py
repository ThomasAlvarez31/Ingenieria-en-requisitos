import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

DATABASE = 'panaderia.db'

# Simulación de Base de Datos de Productos (Código de barras -> Nombre, Horas de duración)
CATALOGO_BARRAAS = {
    "78011111": {"nombre": "Pie de Limón Premium", "horas": 72},
    "78022222": {"nombre": "Tarta de Tres Leches", "horas": 48},
    "78033333": {"nombre": "Pan de Pascua / Especial", "horas": 120},
    "78044444": {"nombre": "Croissant de Mantequilla", "horas": 36},
    "78055555": {"nombre": "Muffin de Arándano", "horas": 48}
}

# Mapeo Industrial: Un color único para cada día de la semana
COLORES_DIAS = {
    0: "Lunes - Verde 🟢",
    1: "Martes - Azul 🔵",
    2: "Miércoles - Amarillo 🟡",
    3: "Jueves - Naranja 🟠",
    4: "Viernes - Morado 🟣",
    5: "Sábado - Rosado 🌸",
    6: "Domingo - Rojo 🔴"
}

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            producto TEXT NOT NULL,
            color TEXT NOT NULL,
            fecha_vencimiento TEXT NOT NULL,
            estado TEXT DEFAULT 'En Vitrina'
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/api/producto/<codigo_barras>', methods=['GET'])
def buscar_por_codigo(codigo_barras):
    prod = CATALOGO_BARRAAS.get(codigo_barras)
    if not prod:
        return jsonify({"error": "Código de barras no registrado"}), 404
    
    dia_semana_hoy = datetime.now().weekday() 
    color_automatico = COLORES_DIAS[dia_semana_hoy]
    
    return jsonify({
        "nombre": prod["nombre"],
        "horas_duracion": prod["horas"],
        "color_asignado": color_automatico
    })

@app.route('/api/lotes', methods=['GET'])
def get_lotes():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, producto, color, fecha_vencimiento, estado FROM lotes")
    rows = cursor.fetchall()
    conn.close()
    
    lotes = []
    ahora = datetime.now()
    
    for r in rows:
        fecha_venc = datetime.strptime(r[3], '%Y-%m-%d %H:%M')
        tiempo_restante = fecha_venc - ahora
        
        alerta = False
        if timedelta(hours=0) < tiempo_restante <= timedelta(hours=24) and r[4] == 'En Vitrina':
            alerta = True
            
        lotes.append({
            "id": r[0], "producto": r[1], "color": r[2],
            "fecha_vencimiento": r[3], "estado": r[4], "alerta": alerta
        })
    return jsonify(lotes)

@app.route('/api/lotes', methods=['POST'])
def add_lote():
    data = request.json
    producto = data.get('producto')
    color = data.get('color')
    horas = int(data.get('horas_duracion', 72))
    
    fecha_venc = datetime.now() + timedelta(hours=horas)
    fecha_venc_str = fecha_venc.strftime('%Y-%m-%d %H:%M')
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO lotes (producto, color, fecha_vencimiento) VALUES (?, ?, ?)",
                   (producto, color, fecha_venc_str))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"}), 201

# --- NUEVA RUTA PARA ELIMINAR ---
@app.route('/api/lotes/<int:lote_id>', methods=['DELETE'])
def eliminar_lote(lote_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM lotes WHERE id = ?", (lote_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"}), 200

if __name__ == '__main__':
    init_db()
    app.run(port=5000, debug=True)