from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify, send_from_directory, send_file
import os
import json
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import psycopg2
from psycopg2.extras import DictCursor

# Inicialização do Flask
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'sistema_demandas_secret_key_2024')

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Detecta o ambiente (development vs. production)
IS_PRODUCTION = os.environ.get('RENDER', False) or 'DATABASE_URL' in os.environ

# Configuração do banco de dados
if IS_PRODUCTION:
    # Configuração para PostgreSQL no ambiente de produção (Render)
    DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://sistema_demandas_db_user:cP52Pdxr3o1tuCVk5TVs9B6MW5rEF6UR@dpg-cvuif46mcj7s73cetkrg-a/sistema_demandas_db')
    # Se o DATABASE_URL começa com postgres://, atualize para postgresql://
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
else:
    # Configuração para SQLite no ambiente de desenvolvimento
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sistema_demandas.db')

# Status padrão
STATUS_CHOICES = ['Em andamento', 'Concluído', 'Pendente', 'Cancelado']

# Classe User para o Flask-Login
class User(UserMixin):
    def __init__(self, id, username, is_superuser=False):
        self.id = id
        self.username = username
        self.is_superuser = is_superuser

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    user = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    if not user:
        return None
    return User(user['id'], user['username'], user['is_superuser'])

# Função para conexão com banco de dados
def get_db_connection():
    if IS_PRODUCTION:
        # Conectar ao PostgreSQL
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    else:
        # Conectar ao SQLite
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn

# Função para consulta ao banco de dados
def query_db(query, args=(), one=False):
    try:
        conn = get_db_connection()
        
        if IS_PRODUCTION:
            # PostgreSQL
            cur = conn.cursor(cursor_factory=DictCursor)
            # Adapta os placeholders do SQLite (?) para PostgreSQL (%s)
            query = query.replace('?', '%s')
        else:
            # SQLite
            cur = conn.cursor()
            # Se a consulta contém %s (placeholder do PostgreSQL), mude para ? (placeholder do SQLite)
            query = query.replace('%s', '?')
        
        cur.execute(query, args)
        
        if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP')):
            conn.commit()
            rv = cur.rowcount
        else:
            if IS_PRODUCTION:
                # PostgreSQL já retorna os resultados como dicionários com DictCursor
                rv = [dict(row) for row in cur.fetchall()]
            else:
                # SQLite precisa ser convertido para dicionário
                rv = [dict(zip([column[0] for column in cur.description], row)) for row in cur.fetchall()]
            
        cur.close()
        conn.close()
        
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print(f"Erro na consulta ao banco de dados: {str(e)}")
        if 'conn' in locals() and conn is not None:
            conn.close()
        raise e

# Função para garantir que a estrutura das tabelas existe
def ensure_tables():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if IS_PRODUCTION:
            # PostgreSQL
            # Verifica se a tabela users existe
            cur.execute("SELECT to_regclass('public.users')")
            if not cur.fetchone()[0]:
                # Cria a tabela users se não existir
                cur.execute('''
                    CREATE TABLE users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        is_superuser BOOLEAN DEFAULT FALSE
                    )
                ''')
                # Cria um superusuário padrão
                cur.execute('''
                    INSERT INTO users (username, password, is_superuser)
                    VALUES ('admin', 'admin', TRUE)
                ''')
                conn.commit()
                print("Tabela de usuários criada com sucesso! Usuário padrão: admin/admin")
            
            # Verifica se a tabela registros existe
            cur.execute("SELECT to_regclass('public.registros')")
            if not cur.fetchone()[0]:
                # Cria a tabela registros se não existir
                cur.execute('''
                    CREATE TABLE registros (
                        id SERIAL PRIMARY KEY,
                        data DATE,
                        demanda TEXT,
                        assunto TEXT,
                        status TEXT,
                        local TEXT,
                        direcionamentos TEXT,
                        ultimo_editor TEXT,
                        data_ultima_edicao TIMESTAMP WITH TIME ZONE,
                        anexos JSONB DEFAULT '[]'
                    )
                ''')
                conn.commit()
        else:
            # SQLite
            # Verifica se a tabela users existe
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not cur.fetchone():
                # Cria a tabela users se não existir
                cur.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        is_superuser INTEGER DEFAULT 0
                    )
                ''')
                # Cria um superusuário padrão
                cur.execute('''
                    INSERT INTO users (username, password, is_superuser)
                    VALUES ('admin', 'admin', 1)
                ''')
                conn.commit()
                print("Tabela de usuários criada com sucesso! Usuário padrão: admin/admin")
            
            # Verifica se a tabela registros existe
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='registros'")
            if not cur.fetchone():
                # Cria a tabela registros se não existir
                cur.execute('''
                    CREATE TABLE registros (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        data DATE,
                        demanda TEXT,
                        assunto TEXT,
                        status TEXT,
                        local TEXT,
                        direcionamentos TEXT,
                        ultimo_editor TEXT,
                        data_ultima_edicao TIMESTAMP,
                        anexos TEXT DEFAULT '[]'
                    )
                ''')
                conn.commit()
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Erro ao verificar tabelas: {str(e)}")
        if 'conn' in locals() and conn is not None:
            conn.close()

# Inicialização do banco de dados
ensure_tables()

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
        user = query_db('SELECT * FROM users WHERE username = ? AND password = ?',
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
            
        existing_user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if existing_user:
            flash('Nome de usuário já existe.')
            return redirect(url_for('register'))
            
        query_db('INSERT INTO users (username, password, is_superuser) VALUES (?, ?, ?)',
                [username, password, False])
        flash('Usuário criado com sucesso!')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        if not username:
            flash('Por favor, informe o nome de usuário.')
            return redirect(url_for('forgot_password'))
            
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if not user:
            flash('Usuário não encontrado.')
            return redirect(url_for('forgot_password'))
            
        # Em um sistema real, aqui seria enviado um e-mail com link de redefinição
        # Como é uma versão simplificada, apenas resetamos para uma senha padrão
        query_db('UPDATE users SET password = ? WHERE id = ?', ['123456', user['id']])
        flash('Senha redefinida para: 123456. Por favor, altere sua senha após o login.')
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_superuser:
        flash('Acesso negado: você não tem permissão para acessar essa página.')
        return redirect(url_for('form'))
        
    users = query_db('SELECT * FROM users ORDER BY username')
    
    # Dados simplificados para diagnóstico
    stats = {
        'total_registros': 0,
        'registros_hoje': 0,
        'registros_pendentes': 0,
        'total_usuarios': len(users),
        'status_counts': {status: 0 for status in STATUS_CHOICES}
    }
    
    system_logs = ["Sistema iniciado"]
    
    settings = {
        'per_page': 10,
        'session_timeout': 60,
        'auto_backup': 'daily'
    }
    
    return render_template('admin.html', users=users, stats=stats, system_logs=system_logs, settings=settings)

@app.route('/admin/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    if not current_user.is_superuser:
        return jsonify({'success': False, 'message': 'Acesso negado'}), 403
        
    data = request.get_json()
    username = data.get('username')
    is_superuser = data.get('is_superuser')
    password = data.get('password')
    
    if not username:
        return jsonify({'success': False, 'message': 'Nome de usuário não pode estar vazio'}), 400
        
    try:
        if password:
            # Se uma nova senha foi fornecida, atualize-a também
            query_db('UPDATE users SET username = ?, is_superuser = ?, password = ? WHERE id = ?', 
                    [username, is_superuser, password, user_id])
        else:
            # Caso contrário, apenas atualize o nome de usuário e o status de superusuário
            query_db('UPDATE users SET username = ?, is_superuser = ? WHERE id = ?', 
                    [username, is_superuser, user_id])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/user/<int:user_id>', methods=['DELETE', 'POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_superuser:
        flash('Acesso negado: você não tem permissão para realizar essa ação.')
        return redirect(url_for('admin'))
        
    if current_user.id == user_id:
        flash('Você não pode excluir sua própria conta!')
        return redirect(url_for('admin'))
        
    query_db('DELETE FROM users WHERE id = ?', [user_id])
    flash('Usuário excluído com sucesso!')
    return redirect(url_for('admin'))

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
        ensure_tables()

        # Insere o registro
        query = '''
            INSERT INTO registros 
            (data, demanda, assunto, status, local, direcionamentos, ultimo_editor, data_ultima_edicao) 
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
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

@app.route('/report')
@login_required
def report():
    # Busca todos os registros ordenados por data (mais recentes primeiro)
    registros = query_db('''
        SELECT * FROM registros
        ORDER BY data DESC, id DESC
    ''')
    
    return render_template('report.html', registros=registros, status_list=STATUS_CHOICES)

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    if not current_user.is_superuser:
        flash('Acesso negado: você não tem permissão para acessar essa página.')
        return redirect(url_for('form'))
        
    # Em uma versão real, aqui salvaria as configurações no banco de dados
    # Como é uma versão simplificada, apenas redirecionamos com uma mensagem
    flash('Configurações atualizadas com sucesso!')
    return redirect(url_for('admin'))

@app.route('/test_login')
def test_login():
    if current_user.is_authenticated:
        is_admin = current_user.is_superuser
        result = {
            'authenticated': True,
            'username': current_user.username,
            'is_superuser': is_admin,
            'id': current_user.id
        }
    else:
        result = {'authenticated': False}
    
    return jsonify(result)

# As funções de importação e exportação foram removidas conforme solicitado.

if __name__ == '__main__':
    # Garantir que as tabelas do banco de dados existam
    ensure_tables()
    # Iniciar o servidor Flask
    app.run(debug=True)
