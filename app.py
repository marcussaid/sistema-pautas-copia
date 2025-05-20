from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify, send_from_directory, send_file
import os
import json
from werkzeug.utils import secure_filename
from datetime import datetime, date
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import psycopg2
from psycopg2.extras import DictCursor

# Inicialização do Flask
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'sistema_demandas_secret_key_2024')

# Definir diretório de upload padrão
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
                
            # Verifica se a tabela system_logs existe
            cur.execute("SELECT to_regclass('public.system_logs')")
            if not cur.fetchone()[0]:
                # Cria a tabela system_logs se não existir
                cur.execute('''
                    CREATE TABLE system_logs (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        username TEXT,
                        action TEXT,
                        details TEXT,
                        ip_address TEXT
                    )
                ''')
                # Registra o primeiro log de inicialização do sistema
                cur.execute('''
                    INSERT INTO system_logs (username, action, details)
                    VALUES ('sistema', 'inicialização', 'Sistema iniciado com sucesso')
                ''')
                conn.commit()
                print("Tabela de logs do sistema criada com sucesso!")
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
                
            # Verifica se a tabela system_logs existe
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_logs'")
            if not cur.fetchone():
                # Cria a tabela system_logs se não existir
                cur.execute('''
                    CREATE TABLE system_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        username TEXT,
                        action TEXT,
                        details TEXT,
                        ip_address TEXT
                    )
                ''')
                # Registra o primeiro log de inicialização do sistema
                cur.execute('''
                    INSERT INTO system_logs (username, action, details)
                    VALUES ('sistema', 'inicialização', 'Sistema iniciado com sucesso')
                ''')
                conn.commit()
                print("Tabela de logs do sistema criada com sucesso!")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Erro ao verificar tabelas: {str(e)}")
        if 'conn' in locals() and conn is not None:
            conn.close()

# Inicialização do banco de dados
ensure_tables()

# Função para obter estatísticas dos registros
def get_stats():
    # Conta o total de registros
    total_registros = query_db('SELECT COUNT(*) as count FROM registros', one=True)['count']
    
    # Obtém a data de hoje
    hoje = date.today().strftime('%Y-%m-%d')
    
    # Conta registros de hoje
    registros_hoje = query_db('SELECT COUNT(*) as count FROM registros WHERE data = ?', [hoje], one=True)['count']
    
    # Conta registros pendentes
    registros_pendentes = query_db('SELECT COUNT(*) as count FROM registros WHERE status = ?', ['Pendente'], one=True)['count']
    
    # Conta registros por status
    status_counts = {}
    for status in STATUS_CHOICES:
        count = query_db('SELECT COUNT(*) as count FROM registros WHERE status = ?', [status], one=True)['count']
        status_counts[status] = count
    
    # Retorna as estatísticas
    return {
        'total_registros': total_registros,
        'registros_hoje': registros_hoje,
        'registros_pendentes': registros_pendentes,
        'status_counts': status_counts
    }

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
    
    # Obtém estatísticas atualizadas do banco de dados
    stats = get_stats()
    stats['total_usuarios'] = len(users)
    
    # Busca os logs mais recentes do sistema
    system_logs = query_db('''
        SELECT timestamp, username, action, details, ip_address 
        FROM system_logs 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''')
    
    # Formata os logs para exibição
    formatted_logs = []
    for log in system_logs:
        timestamp = log['timestamp']
        # Formata a data/hora para exibição
        if isinstance(timestamp, str):
            # Analisa a string de data/hora
            try:
                from datetime import datetime
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                # Mantém como string se não conseguir converter
                pass
        
        formatted_log = f"[{timestamp}] {log['username']}: {log['action']} - {log['details']}"
        formatted_logs.append(formatted_log)
    
    settings = {
        'per_page': 10,
        'session_timeout': 60,
        'auto_backup': 'daily'
    }
    
    return render_template('admin.html', users=users, stats=stats, system_logs=formatted_logs, settings=settings)

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

@app.route('/estatisticas')
@login_required
def estatisticas():
    # Obtém estatísticas para o dashboard
    stats = get_stats()
    
    # Busca os registros para a tabela de demandas recentes
    registros = query_db('''SELECT * FROM registros ORDER BY data DESC, id DESC''')
    
    return render_template('estatisticas.html', registros=registros, stats=stats)

@app.route('/report')
@login_required
def report():
    # Busca todos os registros ordenados por data (mais recentes primeiro)
    registros = query_db('''
        SELECT * FROM registros
        ORDER BY data DESC, id DESC
    ''')

    # Converte o campo anexos de JSON string para objeto Python para cada registro
    for registro in registros:
        try:
            if 'anexos' in registro and registro['anexos']:
                if isinstance(registro['anexos'], str):
                    registro['anexos'] = json.loads(registro['anexos'])
                # Se já for objeto (PostgreSQL JSONB), mantém como está
                # Garantir que é uma lista
                if not isinstance(registro['anexos'], list):
                    registro['anexos'] = []
            else:
                registro['anexos'] = []
        except Exception:
            registro['anexos'] = []

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

# Rotas para edição de registros
@app.route('/edit/<int:registro_id>', methods=['GET', 'POST'])
@login_required
def edit_registro(registro_id):
    # Busca o registro no banco de dados
    registro = query_db('SELECT * FROM registros WHERE id = ?', [registro_id], one=True)
    
    if not registro:
        flash('Registro não encontrado.')
        return redirect(url_for('report'))
    
    # Converte a string JSON de anexos para lista Python
    if 'anexos' in registro and registro['anexos']:
        try:
            if isinstance(registro['anexos'], str):
                registro['anexos'] = json.loads(registro['anexos'])
            # Se já for um objeto (no caso do PostgreSQL com JSONB), mantém como está
        except json.JSONDecodeError:
            registro['anexos'] = []
    else:
        registro['anexos'] = []
    
    if request.method == 'POST':
        # Obtém os dados do formulário
        data = request.form.get('data', '').strip()
        demanda = request.form.get('demanda', '').strip()
        assunto = request.form.get('assunto', '').strip()
        status = request.form.get('status', '').strip()
        local = request.form.get('local', '').strip()
        direcionamentos = request.form.get('direcionamentos', '').strip()
        
        # Valida os dados
        if not all([data, demanda, assunto, status, local]):
            flash('Por favor, preencha todos os campos obrigatórios.')
            return render_template('edit.html', registro=registro, status_list=STATUS_CHOICES)
        
        if status not in STATUS_CHOICES:
            flash('Por favor, selecione um status válido.')
            return render_template('edit.html', registro=registro, status_list=STATUS_CHOICES)
        
        # Atualiza o registro
        query_db('''
            UPDATE registros 
            SET data = ?, demanda = ?, assunto = ?, status = ?, local = ?, 
                direcionamentos = ?, ultimo_editor = ?, data_ultima_edicao = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', [data, demanda, assunto, status, local, direcionamentos, current_user.username, registro_id])
        
        flash('Registro atualizado com sucesso!')
        return redirect(url_for('report'))
    
    # Renderiza o template com os dados do registro
    return render_template('edit.html', registro=registro, status_list=STATUS_CHOICES)

# Rotas para gerenciamento de anexos
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

@app.route('/upload_anexo/<int:registro_id>', methods=['POST'])
@login_required
def upload_anexo(registro_id):
    # Verifica se o registro existe
    registro = query_db('SELECT * FROM registros WHERE id = ?', [registro_id], one=True)
    if not registro:
        return jsonify({'error': 'Registro não encontrado.'}), 404
    
    # Verifica se um arquivo foi enviado
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado.'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nenhum arquivo selecionado.'}), 400
    
    # Gera um nome seguro para o arquivo
    filename = secure_filename(file.filename)
    unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    
    # Configura o cliente S3
    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
        region_name=os.environ.get('AWS_DEFAULT_REGION')
    )
    
    bucket_name = os.environ.get('AWS_BUCKET_NAME')
    
    try:
        # Faz upload do arquivo para o bucket S3
        s3_client.upload_fileobj(file, bucket_name, unique_filename)
    except (NoCredentialsError, ClientError) as e:
        app.logger.error(f"Erro ao fazer upload para S3: {str(e)}")
        return jsonify({'error': f'Erro ao fazer upload para S3: {str(e)}'}), 500
    
    # Obtém os anexos atuais
    try:
        if 'anexos' in registro and registro['anexos']:
            if isinstance(registro['anexos'], str):
                anexos = json.loads(registro['anexos'])
            else:
                anexos = registro['anexos']
        else:
            anexos = []
    except (json.JSONDecodeError, TypeError):
        anexos = []
    
    # Gera um ID único para o anexo
    import uuid
    anexo_id = str(uuid.uuid4())
    
    # Adiciona o novo anexo com a URL do S3
    s3_url = f"https://{bucket_name}.s3.{os.environ.get('AWS_DEFAULT_REGION')}.amazonaws.com/{unique_filename}"
    novo_anexo = {
        'id': anexo_id,
        'nome_original': filename,
        'nome_sistema': unique_filename,
        'url': s3_url,
        'data_upload': datetime.now().isoformat(),
        'tamanho': file.content_length if file.content_length else 0
    }
    anexos.append(novo_anexo)
    
    # Atualiza o registro no banco de dados
    if IS_PRODUCTION:
        # PostgreSQL (JSONB)
        query_db('UPDATE registros SET anexos = %s WHERE id = %s', [json.dumps(anexos), registro_id])
    else:
        # SQLite (TEXT)
        query_db('UPDATE registros SET anexos = ? WHERE id = ?', [json.dumps(anexos), registro_id])
    
    return jsonify({
        'success': True,
        'anexo': novo_anexo
    })

@app.route('/download_anexo/<int:registro_id>/<anexo_id>')
@login_required
def download_anexo(registro_id, anexo_id):
    # Verifica se o registro existe
    registro = query_db('SELECT * FROM registros WHERE id = ?', [registro_id], one=True)
    if not registro:
        flash('Registro não encontrado.')
        return redirect(url_for('report'))
    
    # Obtém os anexos
    try:
        if isinstance(registro['anexos'], str):
            anexos = json.loads(registro['anexos'])
        else:
            anexos = registro['anexos']
    except (json.JSONDecodeError, TypeError):
        anexos = []
    
    # Procura o anexo pelo ID
    anexo = next((a for a in anexos if a['id'] == anexo_id), None)
    if not anexo:
        flash('Anexo não encontrado.')
        return redirect(url_for('edit_registro', registro_id=registro_id))
    
    # Define o caminho do arquivo
    filepath = os.path.join(app.root_path, 'uploads', anexo['nome_sistema'])
    
    # Verifica se o arquivo existe
    if not os.path.exists(filepath):
        flash('Arquivo não encontrado no servidor.')
        return redirect(url_for('edit_registro', registro_id=registro_id))
    
    # Envia o arquivo para download
    return send_file(
        filepath,
        download_name=anexo['nome_original'],
        as_attachment=True
    )

@app.route('/delete_anexo/<int:registro_id>/<anexo_id>', methods=['DELETE'])
@login_required
def delete_anexo(registro_id, anexo_id):
    # Verifica se o registro existe
    registro = query_db('SELECT anexos FROM registros WHERE id = ?', [registro_id], one=True)
    if not registro:
        return jsonify({'success': False, 'error': 'Registro não encontrado'}), 404
    
    try:
        # Carrega os anexos existentes
        anexos = json.loads(registro['anexos']) if registro['anexos'] else []
        
        # Encontra o anexo pelo ID
        anexo_encontrado = None
        for anexo in anexos:
            if anexo.get('id') == anexo_id:
                anexo_encontrado = anexo
                break
        
        if not anexo_encontrado:
            return jsonify({'success': False, 'error': 'Anexo não encontrado'}), 404
        
        # Remove o anexo da lista
        anexos = [a for a in anexos if a.get('id') != anexo_id]
        
        # Tenta remover o arquivo físico, se existir
        filepath = os.path.join(app.config.get('UPLOAD_FOLDER', ''), anexo_encontrado.get('nome_sistema', ''))
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
            else:
                app.logger.warning(f"Arquivo para exclusão não encontrado: {filepath}")
        except Exception as e:
            app.logger.error(f"Erro ao excluir arquivo físico: {str(e)}")
        
        # Log para depuração do tipo e valor de anexos antes da atualização
        app.logger.debug(f"Tipo de anexos antes do update: {type(anexos)}")
        app.logger.debug(f"Valor de anexos antes do update: {anexos}")
        
        # Atualiza o banco de dados
        # Como o ambiente de produção é PostgreSQL, usa json.dumps diretamente
        query_db('UPDATE registros SET anexos = %s, data_ultima_edicao = CURRENT_TIMESTAMP, ultimo_editor = %s WHERE id = %s', 
                 [json.dumps(anexos), current_user.username, registro_id])
    
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Rota para importação de CSV
@app.route('/import_csv', methods=['GET', 'POST'])
@login_required
def import_csv():
    if not current_user.is_superuser:
        flash('Acesso negado: você não tem permissão para importar dados.')
        return redirect(url_for('form'))
    
    if request.method == 'POST':
        # Verifica se é uma confirmação de importação após preview
        if 'confirm' in request.form:
            print("Processando confirmação de importação...")
            # Recupera os dados da sessão
            if 'import_data' not in session:
                flash('Dados para importação não encontrados. Por favor, tente novamente.')
                return redirect(url_for('import_csv'))
            
            # Obtém os dados da sessão
            import_data = session['import_data']
            print(f"Dados recuperados da sessão: {len(import_data)} linhas no total")
            
            # Remove o cabeçalho
            data_rows = import_data[1:] if len(import_data) > 1 else []
            print(f"Dados sem cabeçalho: {len(data_rows)} linhas para processamento")
            
            # Importa os dados
            registros_importados = 0
            registros_com_erro = 0
            
            # Inserir os registros no banco de dados
            for registro in data_rows:
                try:
                    print(f"Processando linha {len(data_rows) - len(data_rows) + 1}: {registro}")
                    if len(registro) < 6:  # Mínimo de colunas necessárias
                        error_msg = f"Linha {len(data_rows) - len(data_rows) + 1}: Número insuficiente de colunas ({len(registro)}/6)"
                        print(error_msg)
                        error_details.append(error_msg)
                        error_count += 1
                        continue
                    
                    # Extrai os dados da linha
                    data, demanda, assunto, local, direcionamentos, status = [str(col).strip() for col in registro[:6]]
                    
                    # Validações básicas
                    if not data or not demanda or not assunto:
                        error_msg = f"Linha {len(data_rows) - len(data_rows) + 1}: Campos obrigatórios vazios (data, demanda ou assunto)"
                        print(error_msg)
                        error_details.append(error_msg)
                        error_count += 1
                        continue
                    
                    # Converte a data (tenta diferentes formatos)
                    data_formatada = None
                    
                    # Tenta formato DD/MM/AAAA
                    if '/' in data:
                        try:
                            data_parts = data.split('/')
                            if len(data_parts) == 3:
                                # Garante que todos os componentes são numéricos
                                if all(part.isdigit() for part in data_parts):
                                    # Converte para formato ISO (AAAA-MM-DD)
                                    data_formatada = f"{data_parts[2].zfill(4)}-{data_parts[1].zfill(2)}-{data_parts[0].zfill(2)}"
                        except Exception as e:
                            print(f"Erro ao processar data (formato DD/MM/AAAA): {str(e)}")
                    
                    # Tenta formato AAAA-MM-DD
                    elif '-' in data:
                        try:
                            data_parts = data.split('-')
                            if len(data_parts) == 3:
                                # Garante que todos os componentes são numéricos
                                if all(part.isdigit() for part in data_parts):
                                    # Já está no formato ISO
                                    data_formatada = f"{data_parts[0].zfill(4)}-{data_parts[1].zfill(2)}-{data_parts[2].zfill(2)}"
                        except Exception as e:
                            print(f"Erro ao processar data (formato AAAA-MM-DD): {str(e)}")
                    
                    # Se a data não foi formatada com sucesso, tenta hoje
                    if not data_formatada:
                        from datetime import date
                        data_formatada = date.today().isoformat()
                        print(f"Usando data de hoje ({data_formatada}) para linha {len(data_rows) - len(data_rows) + 1}")
                    
                    # Valida o status
                    status_original = status
                    if not status or status not in STATUS_CHOICES:
                        status = 'Pendente'  # Default
                        print(f"Status inválido na linha {len(data_rows) - len(data_rows) + 1}: '{status_original}', usando 'Pendente'")
                    
                    print(f"Dados formatados: data={data_formatada}, demanda='{demanda}', status='{status}'")
                    
                    # Insere no banco de dados
                    try:
                        query_db('''
                            INSERT INTO registros 
                            (data, demanda, assunto, status, local, direcionamentos, ultimo_editor, data_ultima_edicao) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ''', [
                            data_formatada, demanda, assunto, status, local, direcionamentos, 
                            current_user.username
                        ])
                        
                        registros_importados += 1
                        print(f"Linha {len(data_rows) - len(data_rows) + 1} importada com sucesso")
                    except Exception as e:
                        error_msg = f"Linha {len(data_rows) - len(data_rows) + 1}: Erro ao inserir no banco de dados: {str(e)}"
                        print(error_msg)
                        error_details.append(error_msg)
                        error_count += 1
                
                except Exception as e:
                    error_msg = f"Linha {len(data_rows) - len(data_rows) + 1}: Erro inesperado: {str(e)}"
                    print(error_msg)
                    error_details.append(error_msg)
                    error_count += 1
            
            # Limpa os dados da sessão
            session.pop('import_data', None)
            
            # Registrar no log a importação
            log_activity(
                username=current_user.username,
                action='importação CSV',
                details=f"Importação concluída: {registros_importados} registros importados, {len(error_details)} com erro, {len(error_details) - registros_importados} inválidos",
                ip_address=request.remote_addr
            )
            
            # Retorna o resultado
            flash(f'Importação concluída com sucesso! Foram importados {registros_importados} registros. {len(error_details) - registros_importados} registros tiveram erros e não foram importados.')
            return redirect(url_for('report'))
        
        # Caso contrário, é o upload inicial do arquivo
        if 'file' not in request.files:
            flash('Nenhum arquivo enviado.')
            return redirect(url_for('import_csv'))
        
        file = request.files['file']
        if file.filename == '':
            flash('Nenhum arquivo selecionado.')
            return redirect(url_for('import_csv'))
        
        if not file.filename.lower().endswith('.csv'):
            flash('Por favor, selecione um arquivo CSV.')
            return redirect(url_for('import_csv'))
        
        # Tenta ler o arquivo CSV com diferentes codificações e delimitadores
        import csv
        
        # Lista de codificações e delimitadores para tentar
        encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
        delimiters = [',', ';', '\t']
        
        file_content = file.read()  # Lê o conteúdo uma vez
        
        success = False
        data = None
        error_message = "Não foi possível processar o arquivo CSV."
        
        for encoding in encodings:
            if success:
                break
                
            try:
                print(f"Tentando decodificar com {encoding}")
                decoded_content = file_content.decode(encoding)
                
                for delimiter in delimiters:
                    try:
                        print(f"Tentando delimitador '{delimiter}'")
                        csv_reader = csv.reader(decoded_content.splitlines(), delimiter=delimiter)
                        data = [row for row in csv_reader]
                        
                        # Verifica se o arquivo tem dados válidos (pelo menos 2 linhas)
                        if len(data) >= 2 and len(data[0]) >= 3:  # Pelo menos cabeçalho e 1 linha de dados
                            success = True
                            print(f"Sucesso com encoding={encoding}, delimiter='{delimiter}', encontradas {len(data)} linhas")
                            break
                    except Exception as e:
                        print(f"Erro com delimitador '{delimiter}': {str(e)}")
            except Exception as e:
                print(f"Erro com encoding {encoding}: {str(e)}")
        
        if not success or not data:
            flash(error_message)
            return redirect(url_for('import_csv'))
        
        # Verifica se o arquivo tem dados
        if len(data) < 2:  # Pelo menos cabeçalho + 1 linha
            flash('Arquivo CSV vazio ou inválido.')
            return redirect(url_for('import_csv'))
        
        # Diagnostica o conteúdo do arquivo
        print(f"Cabeçalho: {data[0]}")
        for i, row in enumerate(data[1:3], start=1):  # Mostra até 2 linhas de dados
            print(f"Linha {i}: {row}")
        
        # Guarda os dados na sessão para confirmação
        session['import_data'] = data
        
        # Renderiza o template com preview
        return render_template('import_csv.html', preview_data=data)
    
    # Método GET - exibe a página de upload
    return render_template('import_csv.html')

# Rota para pesquisa avançada
@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        # Obtém os parâmetros de pesquisa
        termo = request.form.get('termo', '').strip()
        status = request.form.get('status', '').strip()
        data_inicio = request.form.get('data_inicio', '').strip()
        data_fim = request.form.get('data_fim', '').strip()
        
        # Constrói a query dinâmica
        query = 'SELECT * FROM registros WHERE 1=1'
        params = []
        
        if termo:
            query += ' AND (demanda LIKE ? OR assunto LIKE ? OR local LIKE ? OR direcionamentos LIKE ?)'
            termo_search = f'%{termo}%'
            params.extend([termo_search, termo_search, termo_search, termo_search])
        
        if status and status != 'Todos':
            query += ' AND status = ?'
            params.append(status)
        
        if data_inicio:
            query += ' AND data >= ?'
            params.append(data_inicio)
        
        if data_fim:
            query += ' AND data <= ?'
            params.append(data_fim)
        
        # Ordenação
        query += ' ORDER BY data DESC, id DESC'
        
        # Executa a pesquisa
        registros = query_db(query, params)
        
        # Renderiza a página de resultados
        return render_template('view_results.html', registros=registros, search_params={
            'termo': termo,
            'status': status,
            'data_inicio': data_inicio,
            'data_fim': data_fim
        })
    
    # Método GET - redireciona para a página de relatório
    return redirect(url_for('report'))

# Rota para excluir registros
@app.route('/delete_registro/<int:registro_id>', methods=['POST'])
@login_required
def delete_registro(registro_id):
    try:
        # Verifica se o usuário é superusuário
        if not current_user.is_superuser:
            return jsonify({'success': False, 'message': 'Acesso negado: apenas administradores podem excluir registros.'}), 403
        
        # Busca o registro para confirmar que existe
        registro = query_db('SELECT * FROM registros WHERE id = ?', [registro_id], one=True)
        if not registro:
            return jsonify({'success': False, 'message': 'Registro não encontrado.'}), 404
        
        # Registra no log a ação de exclusão
        detalhes = f"Registro excluído: ID={registro_id}, Demanda='{registro['demanda']}', Data='{registro['data']}'"
        log_activity(
            username=current_user.username,
            action='exclusão de registro',
            details=detalhes,
            ip_address=request.remote_addr
        )
        
        # Exclui o registro
        query_db('DELETE FROM registros WHERE id = ?', [registro_id])
        
        # Retorna sucesso
        return jsonify({'success': True, 'message': 'Registro excluído com sucesso!'})
    except Exception as e:
        print(f"Erro ao excluir registro {registro_id}: {str(e)}")
        return jsonify({'success': False, 'message': f'Erro ao excluir registro: {str(e)}'}), 500

# Rota para exportação de CSV
@app.route('/export_csv', methods=['GET'])
@login_required
def export_csv():
    try:
        print("Função export_csv iniciada")
        # Busca todos os registros ou aplica filtros se houver
        query = 'SELECT * FROM registros WHERE 1=1'
        params = []
        
        # Aplica filtros se estiverem na URL
        status = request.args.get('status')
        termo = request.args.get('termo')
        data_inicio = request.args.get('data_inicio')
        data_fim = request.args.get('data_fim')
        
        print(f"Filtros recebidos: status={status}, termo={termo}, data_inicio={data_inicio}, data_fim={data_fim}")
        
        if termo:
            query += ' AND (demanda LIKE ? OR assunto LIKE ? OR local LIKE ? OR direcionamentos LIKE ?)'
            termo_search = f'%{termo}%'
            params.extend([termo_search, termo_search, termo_search, termo_search])
        
        if status and status != 'Todos':
            query += ' AND status = ?'
            params.append(status)
        
        if data_inicio:
            query += ' AND data >= ?'
            params.append(data_inicio)
        
        if data_fim:
            query += ' AND data <= ?'
            params.append(data_fim)
        
        # Ordenação
        query += ' ORDER BY data DESC, id DESC'
        
        print(f"Query: {query}")
        print(f"Parâmetros: {params}")
        
        # Executa a pesquisa
        registros = query_db(query, params)
        print(f"Número de registros encontrados: {len(registros)}")
        
        # Gera o conteúdo do CSV
        import csv
        from io import StringIO
        
        # Cria um buffer na memória
        output = StringIO()
        
        # Adiciona BOM UTF-8 para garantir que Excel e outros programas reconheçam os acentos
        output.write('\ufeff')
        
        writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_MINIMAL)
        
        # Escreve o cabeçalho
        writer.writerow(['Data', 'Demanda', 'Assunto', 'Local', 'Direcionamentos', 'Status'])
        
        # Escreve as linhas de dados
        for registro in registros:
            try:
                writer.writerow([
                    registro.get('data', ''),
                    registro.get('demanda', ''),
                    registro.get('assunto', ''),
                    registro.get('local', ''),
                    registro.get('direcionamentos', ''),
                    registro.get('status', '')
                ])
            except Exception as e:
                print(f"Erro ao processar registro {registro}: {str(e)}")
        
        # Prepara o arquivo para download
        output_value = output.getvalue()
        response = make_response(output_value)
        response.headers['Content-Disposition'] = f'attachment; filename=demandas_{datetime.now().strftime("%Y-%m-%d")}.csv'
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Length'] = len(output_value.encode('utf-8'))  # Usa encode para obter o tamanho em bytes
        response.headers['Cache-Control'] = 'no-cache'
        
        print("Arquivo CSV gerado com sucesso")
        return response
    except Exception as e:
        import traceback
        print(f"Erro ao exportar dados: {str(e)}")
        print(traceback.format_exc())
        flash(f'Erro ao exportar dados: {str(e)}')
        return redirect(url_for('report'))

@app.route('/test_export')
@login_required
def test_export():
    """
    Rota para testar a exportação
    """
    try:
        # Tenta buscar alguns registros diretamente
        registros = query_db('SELECT * FROM registros LIMIT 5')
        
        if not registros:
            return "Não há registros para exportar. Primeiro adicione alguns registros."
        
        # Converte registros para HTML para visualização
        html = "<h1>Teste de Exportação</h1>"
        html += "<p>Registros encontrados: " + str(len(registros)) + "</p>"
        html += "<table border='1'><tr><th>ID</th><th>Data</th><th>Demanda</th><th>Status</th></tr>"
        
        for reg in registros:
            html += f"<tr><td>{reg.get('id', '')}</td><td>{reg.get('data', '')}</td><td>{reg.get('demanda', '')}</td><td>{reg.get('status', '')}</td></tr>"
        
        html += "</table>"
        html += "<p><a href='/export_csv'>Clique aqui para testar a exportação</a></p>"
        html += "<p><a href='/report'>Voltar para o relatório</a></p>"
        
        return html
        
    except Exception as e:
        import traceback
        error_html = "<h1>Erro no teste</h1>"
        error_html += f"<p>Erro: {str(e)}</p>"
        error_html += f"<pre>{traceback.format_exc()}</pre>"
        error_html += "<p><a href='/report'>Voltar para o relatório</a></p>"
        return error_html

# Rota para gerar um arquivo de exemplo CSV com codificação correta
@app.route('/gerar_exemplo_csv')
def gerar_exemplo_csv():
    try:
        # Conteúdo do exemplo CSV
        csv_content = """Data;Demanda;Assunto;Local;Direcionamentos;Status
01/06/2024;Fazer relatório mensal;Relatório Financeiro;Departamento Financeiro;Enviar para o diretor financeiro até dia 10;Em andamento
15/06/2024;Reunião com fornecedores;Contratos;Sala de Reuniões;Preparar apresentação e material de apoio;Pendente
20/06/2024;Entrega de documentos;Documentação Fiscal;Setor Jurídico;Coletar assinaturas necessárias;Concluído"""
        
        # Adiciona BOM UTF-8 para garantir que Excel e outros programas reconheçam os acentos
        response = make_response('\ufeff' + csv_content)
        response.headers['Content-Disposition'] = 'attachment; filename=exemplo_importacao.csv'
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Length'] = len(('\ufeff' + csv_content).encode('utf-8'))
        
        return response
    except Exception as e:
        return f"Erro ao gerar arquivo de exemplo: {str(e)}"

def log_activity(username, action, details, ip_address=None):
    """
    Registra uma atividade no log do sistema
    
    Args:
        username: Nome do usuário que realizou a ação
        action: Tipo de ação (ex: 'login', 'exclusão', 'edição')
        details: Detalhes da ação
        ip_address: Endereço IP (opcional)
    """
    try:
        query_db(
            'INSERT INTO system_logs (username, action, details, ip_address) VALUES (?, ?, ?, ?)',
            [username, action, details, ip_address]
        )
        return True
    except Exception as e:
        print(f"Erro ao registrar log: {str(e)}")
        return False

# Rota para health check
@app.route('/health')
def health_check():
    """
    Rota para verificação de saúde do aplicativo.
    Retorna status 200 OK se o aplicativo estiver funcionando corretamente.
    """
    try:
        # Verifica a conexão com o banco de dados
        query_db('SELECT 1')
        return jsonify({
            'status': 'ok',
            'message': 'Sistema funcionando normalmente',
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        # Se ocorrer algum erro, retorna status 500
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    # Garantir que as tabelas do banco de dados existam
    ensure_tables()
    # Iniciar o servidor Flask
    app.run(debug=True, host='0.0.0.0', port=8000)
