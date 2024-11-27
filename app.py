from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_socketio import SocketIO, send
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from cryptography.fernet import Fernet  # Importamos Fernet
import hmac
import hashlib

app = Flask(__name__)

app.secret_key = "advpjsh"
client = MongoClient("mongodb+srv://davidnet:chetocheto@cluster0.0fkdavr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['Chat']

socketio = SocketIO(app)
bcrypt = Bcrypt(app)

# Clave secreta para generar y verificar HMAC
HMAC_SECRET_KEY = b'123'

# Agrega tu clave generada por Fernet aquí
FERNET_KEY = b'VuhEoPFMuFxxbO_kBuhauHoLddSvfwnwiKCUsycw0Ug='  # Reemplázala con la clave generada

# Crea la instancia de Fernet
fernet = Fernet(FERNET_KEY)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = db.users.find_one({'username': username})  # Busca el usuario en MongoDB

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

        # Verifica si el usuario ya existe en la base de datos
        if db.users.find_one({'username': username}):
            flash('El nombre de usuario ya está en uso.')
            return redirect(url_for('register'))

        # Hashea la contraseña
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Inserta el nuevo usuario en la base de datos
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
    session.pop('username', None)  # Elimina la sesión del usuario
    return redirect(url_for('home'))  # Redirige a la página de inicio

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('home'))

    # Recupera los usuarios conectados de la base de datos
    users = db.users.find()
    user_list = [{'username': user['username'], 'first_name': user.get('first_name', ''), 'last_name': user.get('last_name', ''), 'is_connected': user.get('is_connected', False)} for user in users]

    # Recupera mensajes anteriores de la base de datos
    messages = db.messages.find()
    message_list = [{'username': msg['username'], 'text': fernet.decrypt(msg['text']).decode('utf-8'), 'mac': msg['mac']} for msg in messages]
    
    return render_template('chat.html', username=session['username'], messages=message_list, users=user_list)

@app.route('/profile/<username>')
def view_profile(username):
    user = db.users.find_one({'username': username})
    if user:
        return render_template('profile.html', user=user)
    else:
        flash('Usuario no encontrado.')
        return redirect(url_for('chat'))

@socketio.on('message')
def handle_message(msg):
    username = session.get('username')
    if username:
        # Clave secreta compartida (asegúrate de manejar esto de manera segura en producción)
        secret_key = b'secret_key'

        # Generar la firma HMAC para el mensaje
        message_text = msg['text'].encode('utf-8')  # Asegúrate de codificar el texto
        mac = hmac.new(secret_key, message_text, hashlib.sha256).hexdigest()

        # Encriptar el mensaje con Fernet antes de almacenarlo
        encrypted_message = fernet.encrypt(message_text)

        # Imprimir la firma generada en la terminal
        print(f"Firma generada para el mensaje: {mac}")

        # Guarda el mensaje en la base de datos junto con la firma y el mensaje encriptado
        db.messages.insert_one({'username': username, 'text': encrypted_message, 'mac': mac})

        # Envía el mensaje a todos los usuarios conectados
        send({'username': username, 'text': fernet.decrypt(encrypted_message).decode('utf-8'), 'mac': mac}, broadcast=True)

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        # Marca al usuario como conectado en la base de datos
        db.users.update_one({'username': username}, {'$set': {'is_connected': True}})
        print('Usuario conectado:', username)
    else:
        print('Usuario conectado, pero no hay sesión activa.')

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username:
        # Marca al usuario como desconectado en la base de datos
        db.users.update_one({'username': username}, {'$set': {'is_connected': False}})
        print('Usuario desconectado:', username)
    else:
        print('Usuario desconectado, pero no hay sesión activa.')

if __name__ == '__main__':
    socketio.run(app, debug=True)