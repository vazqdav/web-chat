import eventlet
eventlet.monkey_patch()  # Debe ir al principio del archivo
from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_socketio import SocketIO, send
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from cryptography.fernet import Fernet
import hmac
import hashlib
import os

app = Flask(__name__)

# Clave secreta para sesiones de Flask
app.secret_key = "advpjsh"

# Conexión con MongoDB
client = MongoClient("mongodb+srv://davidnet:chetocheto@cluster0.0fkdavr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['Chat']

# Configuración de Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")  # Habilitar CORS para permitir conexiones desde cualquier origen
bcrypt = Bcrypt(app)

# Clave secreta para HMAC y Fernet
HMAC_SECRET_KEY = b'123'
FERNET_KEY = b'WOLrKb5isgFQ5guZsn03XUtI6YFjjh7JzNDjKGIOsQA='  # Reemplázala con tu clave generada
fernet = Fernet(FERNET_KEY)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = db.users.find_one({'username': username})

    if user and bcrypt.check_password_hash(user['password'], password):
        session['username'] = username
        return redirect(url_for('chat'))
    else:
        flash('Usuario o contraseña incorrectos.')
        return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        matricula = request.form['matricula']
        grupo = request.form['grupo']

        # Verifica si el usuario ya existe
        if db.users.find_one({'username': username}):
            flash('El nombre de usuario ya está en uso.')
            return redirect(url_for('register'))

        # Hashea la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Inserta el nuevo usuario
        db.users.insert_one({
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': hashed_password,
            'matricula': matricula,
            'grupo': grupo
        })
        flash('Registro exitoso. Puedes iniciar sesión.')
        return redirect(url_for('home'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('home'))

    users = db.users.find()
    user_list = [{'username': user['username'], 'first_name': user.get('first_name', ''), 'last_name': user.get('last_name', ''), 'is_connected': user.get('is_connected', False)} for user in users]

    # Recupera mensajes de la base de datos
    messages = db.messages.find()
    message_list = [{'username': msg['username'], 'text': fernet.decrypt(msg['text']).decode('utf-8'), 'mac': msg['mac']} for msg in messages]

    return render_template('chat.html', username=session['username'], messages=message_list, users=user_list)

@socketio.on('message')
def handle_message(msg):
    username = session.get('username')
    if username:
        message_text = msg['text'].encode('utf-8')
        mac = hmac.new(HMAC_SECRET_KEY, message_text, hashlib.sha256).hexdigest()

        # Encriptamos el mensaje antes de guardarlo
        encrypted_message = fernet.encrypt(message_text)

        # Guardamos el mensaje en la base de datos
        db.messages.insert_one({'username': username, 'text': encrypted_message, 'mac': mac})

        # Enviar el mensaje en texto claro a todos los clientes conectados
        send({'username': username, 'text': fernet.decrypt(encrypted_message).decode('utf-8'), 'mac': mac}, broadcast=True)

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        db.users.update_one({'username': username}, {'$set': {'is_connected': True}})
        print(f"Usuario {username} conectado.")
    else:
        print('Usuario conectado sin sesión activa.')

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username:
        db.users.update_one({'username': username}, {'$set': {'is_connected': False}})
        print(f"Usuario {username} desconectado.")
    else:
        print('Usuario desconectado sin sesión activa.')

if __name__ == '__main__':
    port = os.getenv('PORT', 5000)  # Usamos el puerto proporcionado por Render
    socketio.run(app, host='0.0.0.0', port=port)
