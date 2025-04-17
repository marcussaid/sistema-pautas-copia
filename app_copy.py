from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify, send_from_directory, send_file
import psycopg2
from psycopg2.extras import DictCursor
import os
import json
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Inicialização do Flask
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'sistema_demandas_secret_key_2024')

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuração do banco de dados PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://sistema_demandas_db_user:cP52Pdxr3o1tuCVk5TVs9B6MW5rEF6UR@dpg-cvuif46mcj7s73cetkrg-a/sistema_demandas_db')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('form'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = query_db('SELECT * FROM users WHERE username = %s AND password = %s',
                       [username, password], one=True)
        if user:
            login_user(User(user['id'], user['username'], user['is_superuser']))
            return redirect(url_for('form'))
        flash('Usuário ou senha inválidos.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('As senhas não coincidem.')
            return redirect(url_for('register'))
            
        existing_user = query_db('SELECT * FROM users WHERE username = %s', [username], one=True)
        if existing_user:
            flash('Nome de usuário já existe.')
            return redirect(url_for('register'))
            
        query_db('INSERT INTO users (username, password, is_superuser) VALUES (%s, %s, %s)',
                [username, password, False])
        flash('Usuário criado com sucesso!')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/form', methods=['GET'])
@login_required
def form():
    today = datetime.now().strftime('%Y-%m-%d')
    return render_template('form.html', 
                         status_list=STATUS_CHOICES,
                         form_data=request.form,
                         today=today)

@app.route('/submit', methods=['POST'])
@login_required
def submit():
    try:
        data = request.form.get('data', '').strip()
        demanda = request.form.get('demanda', '').strip()
        assunto = request.form.get('assunto', '').strip()
        status = request.form.get('status', '').strip()

        if not all([data, demanda, assunto, status]):
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('form'))

        if status not in STATUS_CHOICES:
            flash('Por favor, selecione um status válido.')
            return redirect(url_for('form'))

        local = request.form.get('local', '').strip()
        direcionamentos = request.form.get('direcionamentos', '').strip()
        
        if not all([data, demanda, assunto, status, local]):
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('form'))

        # Garante que a coluna anexos existe
        ensure_anexos_column()

        # Insere o registro
        query = '''
            INSERT INTO registros 
            (data, demanda, assunto, status, local, direcionamentos, ultimo_editor, data_ultima_edicao) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP AT TIME ZONE 'America/Manaus')
        '''
        query_db(query, [
            data, demanda, assunto, status, local, direcionamentos, 
            current_user.username
        ])
        
        flash('Registro salvo com sucesso!')
        return redirect(url_for('form'))

    except Exception as e:
        flash(f'Erro ao salvar o registro: {str(e)}')
        print(f'Erro ao salvar o registro: {str(e)}')
        return redirect(url_for('form'))

# As funções de importação e exportação foram removidas conforme solicitado.
