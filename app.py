from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify, send_from_directory, send_file
import psycopg2
from psycopg2.extras import DictCursor
import os
import csv
import io
import time
import random
import json
import uuid
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pandas as pd

# Inicialização do Flask
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'sistema_demandas_secret_key_2024')

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Lista de status disponíveis
STATUS_CHOICES = ['Em andamento', 'Concluído', 'Pendente', 'Cancelado']

# Configurações de upload
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
CSV_FOLDER = os.path.join(UPLOAD_FOLDER, 'csv')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'mp3', 'wav'}

# Garante que os diretórios existem
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CSV_FOLDER, exist_ok=True)

# Configuração do banco de dados PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://sistema_demandas_db_user:cP52Pdxr3o1tuCVk5TVs9B6MW5rEF6UR@dpg-cvuif46mcj7s73cetkrg-a/sistema_demandas_db')

def validate_csv_data(df):
    """Valida os dados do CSV"""
    errors = []
    
    # Verifica colunas obrigatórias
    required_columns = ['Data', 'Demanda', 'Assunto', 'Local', 'Status']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        errors.append(f"Colunas obrigatórias faltando: {', '.join(missing_columns)}")
        return errors
    
    # Valida status
    invalid_status = df[~df['Status'].isin(STATUS_CHOICES)]['Status'].unique()
    if len(invalid_status) > 0:
        errors.append(f"Status inválidos encontrados: {', '.join(invalid_status)}")
    
    # Valida datas
    try:
        pd.to_datetime(df['Data'], format='%d/%m/%Y')
    except ValueError as e:
        errors.append("Formato de data inválido. Use DD/MM/AAAA")
    
    # Valida campos obrigatórios não vazios
    for col in ['Demanda', 'Assunto', 'Local']:
        empty_rows = df[df[col].isna()].index.tolist()
        if empty_rows:
            errors.append(f"Campo {col} vazio nas linhas: {', '.join(map(str, empty_rows))}")
    
    return errors

def process_csv_data(df):
    """Processa e formata os dados do CSV para inserção"""
    # Converte datas para o formato correto
    df['Data'] = pd.to_datetime(df['Data'], format='%d/%m/%Y')
    
    # Garante que todas as colunas necessárias existem
    if 'Direcionamentos' not in df.columns:
        df['Direcionamentos'] = None
    
    # Preenche valores nulos
    df = df.fillna('')
    
    return df

@app.route('/importar_csv', methods=['GET', 'POST'])
@login_required
def importar_csv():
    if request.method == 'POST':
        if 'confirm' in request.form:
            # Processa o arquivo temporário salvo
            temp_file = os.path.join(CSV_FOLDER, 'temp_import.csv')
            if not os.path.exists(temp_file):
                flash('Nenhum arquivo para importar. Faça o upload novamente.')
                return redirect(url_for('import_csv'))
            
            try:
                df = pd.read_csv(temp_file)
                df = process_csv_data(df)
                
                # Insere os registros no banco
                for _, row in df.iterrows():
                    query = '''
                        INSERT INTO registros 
                        (data, demanda, assunto, local, direcionamentos, status, 
                         ultimo_editor, data_ultima_edicao, anexos)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 
                                CURRENT_TIMESTAMP AT TIME ZONE 'America/Manaus', '[]'::jsonb)
                    '''
                    query_db(query, [
                        row['Data'].strftime('%Y-%m-%d'),
                        row['Demanda'],
                        row['Assunto'],
                        row['Local'],
                        row['Direcionamentos'],
                        row['Status'],
                        current_user.username
                    ])
                
                # Remove o arquivo temporário
                os.remove(temp_file)
                
                flash(f'{len(df)} registros importados com sucesso!')
                return redirect(url_for('report'))
                
            except Exception as e:
                flash(f'Erro ao importar dados: {str(e)}')
                return redirect(url_for('import_csv'))
        
        if 'file' not in request.files:
            flash('Nenhum arquivo selecionado')
            return redirect(url_for('import_csv'))
            
        file = request.files['file']
        if file.filename == '':
            flash('Nenhum arquivo selecionado')
            return redirect(url_for('import_csv'))
            
        if not file.filename.endswith('.csv'):
            flash('Arquivo deve ser do tipo CSV')
            return redirect(url_for('import_csv'))
            
        try:
            # Salva o arquivo temporariamente
            temp_file = os.path.join(CSV_FOLDER, 'temp_import.csv')
            file.save(temp_file)
            
            # Lê o CSV com pandas
            df = pd.read_csv(temp_file)
            
            # Valida os dados
            if request.form.get('validate_data'):
                errors = validate_csv_data(df)
                if errors:
                    os.remove(temp_file)
                    flash('Erros encontrados no arquivo:')
                    for error in errors:
                        flash(error)
                    return redirect(url_for('import_csv'))
            
            # Se solicitado preview, mostra os primeiros registros
            if request.form.get('preview'):
                preview_data = [df.columns.tolist()] + df.values.tolist()
                return render_template('import_csv.html', preview_data=preview_data)
            
            # Se não precisar de preview, processa diretamente
            df = process_csv_data(df)
            
            # Insere os registros no banco
            for _, row in df.iterrows():
                query = '''
                    INSERT INTO registros 
                    (data, demanda, assunto, local, direcionamentos, status, 
                     ultimo_editor, data_ultima_edicao, anexos)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 
                            CURRENT_TIMESTAMP AT TIME ZONE 'America/Manaus', '[]'::jsonb)
                '''
                query_db(query, [
                    row['Data'].strftime('%Y-%m-%d'),
                    row['Demanda'],
                    row['Assunto'],
                    row['Local'],
                    row['Direcionamentos'],
                    row['Status'],
                    current_user.username
                ])
            
            # Remove o arquivo temporário
            os.remove(temp_file)
            
            flash(f'{len(df)} registros importados com sucesso!')
            return redirect(url_for('report'))
            
        except Exception as e:
            flash(f'Erro ao processar arquivo: {str(e)}')
            if os.path.exists(temp_file):
                os.remove(temp_file)
            return redirect(url_for('import_csv'))
    
    return render_template('import_csv.html')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'mp3', 'wav'}

# Garante que o diretório de uploads existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'sistema_demandas_secret_key_2024')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file):
    """Salva o arquivo e retorna o nome único gerado"""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        return unique_filename
    return None

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static/img'),
                             'favicon.png', mimetype='image/png')

@app.route('/upload_anexo/<int:registro_id>', methods=['POST'])
@login_required
def upload_anexo(registro_id):
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'error': 'Tipo de arquivo não permitido'}), 400
            
        filename = save_file(file)
        if not filename:
            return jsonify({'error': 'Erro ao salvar arquivo'}), 500
            
        # Recupera anexos atuais
        registro = query_db('SELECT anexos FROM registros WHERE id = %s', [registro_id], one=True)
        anexos = registro['anexos'] if registro and registro['anexos'] else []
        
        # Adiciona novo anexo
        novo_anexo = {
            'id': str(uuid.uuid4()),
            'nome_original': secure_filename(file.filename),
            'nome_arquivo': filename,
            'data_upload': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'uploaded_by': current_user.username
        }
        anexos.append(novo_anexo)
        
        # Atualiza registro
        query_db('UPDATE registros SET anexos = %s WHERE id = %s',
                [json.dumps(anexos), registro_id])
        
        return jsonify({'message': 'Arquivo anexado com sucesso', 'anexo': novo_anexo})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_anexo/<int:registro_id>/<anexo_id>')
@login_required
def download_anexo(registro_id, anexo_id):
    try:
        registro = query_db('SELECT anexos FROM registros WHERE id = %s', [registro_id], one=True)
        if not registro or not registro['anexos']:
            return 'Anexo não encontrado', 404
            
        anexo = next((a for a in registro['anexos'] if a['id'] == anexo_id), None)
        if not anexo:
            return 'Anexo não encontrado', 404
            
        return send_from_directory(
            UPLOAD_FOLDER,
            anexo['nome_arquivo'],
            as_attachment=True,
            download_name=anexo['nome_original']
        )
        
    except Exception as e:
        return str(e), 500

@app.route('/delete_anexo/<int:registro_id>/<anexo_id>', methods=['DELETE'])
@login_required
def delete_anexo(registro_id, anexo_id):
    try:
        registro = query_db('SELECT anexos FROM registros WHERE id = %s', [registro_id], one=True)
        if not registro or not registro['anexos']:
            return jsonify({'error': 'Anexo não encontrado'}), 404
            
        anexos = registro['anexos']
        anexo = next((a for a in anexos if a['id'] == anexo_id), None)
        if not anexo:
            return jsonify({'error': 'Anexo não encontrado'}), 404
            
        # Remove arquivo do sistema de arquivos
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, anexo['nome_arquivo']))
        except OSError:
            pass  # Ignora erro se arquivo não existir
            
        # Remove anexo da lista
        anexos = [a for a in anexos if a['id'] != anexo_id]
        
        # Atualiza registro
        query_db('UPDATE registros SET anexos = %s WHERE id = %s',
                [json.dumps(anexos), registro_id])
        
        return jsonify({'message': 'Anexo removido com sucesso'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Configurações padrão do sistema
DEFAULT_SETTINGS = {
    'per_page': 10,
    'session_timeout': 60,  # minutos
    'auto_backup': 'daily'
}

def ensure_anexos_column():
    """Garante que a coluna anexos existe na tabela registros"""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'registros' AND column_name = 'anexos'
                ) THEN
                    ALTER TABLE registros ADD COLUMN anexos JSONB DEFAULT '[]'::jsonb;
                END IF;
            END $$;
        """)
        db.commit()
    finally:
        cur.close()
        db.close()

@app.route('/migrate_db')
@login_required
def migrate_db():
    try:
        ensure_anexos_column()
        return jsonify({'message': 'Migração concluída com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    try:
        # Verifica a conexão com o banco de dados
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT 1")
        cur.close()
        db.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }), 500

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Lista de status disponíveis
STATUS_CHOICES = ['Em andamento', 'Concluído', 'Pendente', 'Cancelado']

# Configuração do banco de dados PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://sistema_demandas_db_user:cP52Pdxr3o1tuCVk5TVs9B6MW5rEF6UR@dpg-cvuif46mcj7s73cetkrg-a/sistema_demandas_db')

class User(UserMixin):
    def __init__(self, id, username=None, is_superuser=False):
        self.id = id
        self.username = username
        self.is_superuser = is_superuser

@login_manager.user_loader
def load_user(user_id):
    user = query_db('SELECT * FROM users WHERE id = %s', [user_id], one=True)
    if user:
        return User(user['id'], user['username'], user['is_superuser'])
    return None

def get_db():
    try:
        # Tenta estabelecer a conexão com retry
        for attempt in range(3):
            try:
                conn = psycopg2.connect(
                    DATABASE_URL,
                    connect_timeout=10,
                    keepalives=1,
                    keepalives_idle=30,
                    keepalives_interval=10,
                    keepalives_count=5
                )
                conn.autocommit = True
                print(f"Conexão estabelecida com sucesso no banco de dados (tentativa {attempt + 1})")
                return conn
            except psycopg2.OperationalError as e:
                if attempt < 2:  # não printa no último retry
                    print(f"Tentativa {attempt + 1} falhou. Tentando novamente... Erro: {e}")
                    time.sleep(1)  # espera 1 segundo antes de tentar novamente
                else:
                    raise  # re-raise na última tentativa
    except Exception as e:
        print(f"Erro fatal ao conectar ao banco de dados: {e}")
        raise

def check_db_connection():
    print("Verificando conexão com o banco de dados...")
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT 1")
        print("Conexão com o banco de dados está funcionando!")
        return True
    except Exception as e:
        print(f"Erro ao verificar conexão com o banco de dados: {e}")
        return False
    finally:
        if 'db' in locals():
            db.close()

def log_system_event(message, level='info'):
    """Registra um evento no log do sistema de forma segura"""
    try:
        query_db('''
            INSERT INTO system_logs (message, level)
            VALUES (%s, %s)
        ''', [message, level])
    except Exception as e:
        print(f"Erro ao registrar log: {e}")

def query_db(query, args=(), one=False):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            print(f"Executando query (tentativa {attempt + 1}): {query[:100]}...")  # Mostra apenas os primeiros 100 caracteres
            db = get_db()
            cur = db.cursor(cursor_factory=DictCursor)
            cur.execute(query, args)
            
            if query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')):
                db.commit()
                affected_rows = cur.rowcount
                print(f"Query executada com sucesso. Linhas afetadas: {affected_rows}")
                cur.close()
                return affected_rows
            else:
                rv = cur.fetchall()
                print(f"Query executada com sucesso. Resultados obtidos: {len(rv)}")
                cur.close()
                return (rv[0] if rv else None) if one else rv
                
        except psycopg2.OperationalError as e:
            print(f"Erro operacional na tentativa {attempt + 1}: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
        except Exception as e:
            print(f"Erro ao executar query: {e}")
            raise
        finally:
            if 'db' in locals():
                db.close()

def init_db():
    print("Iniciando configuração do banco de dados...")
    with app.app_context():
        try:
            db = get_db()
            cur = db.cursor()
            
            # Configura o timezone para Manaus
            cur.execute("SET timezone = 'America/Manaus'")
            
            # Primeiro cria a tabela se não existir
            cur.execute('''
                CREATE TABLE IF NOT EXISTS registros (
                    id SERIAL PRIMARY KEY,
                    data DATE NOT NULL,
                    demanda TEXT NOT NULL,
                    assunto TEXT NOT NULL,
                    status TEXT NOT NULL,
                    local TEXT,
                    direcionamentos TEXT,
                    data_registro TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Manaus')
                )
            ''')

            # Verifica e adiciona a coluna anexos se não existir
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'registros' AND column_name = 'anexos'
                    ) THEN
                        ALTER TABLE registros ADD COLUMN anexos JSONB DEFAULT '[]'::jsonb;
                    END IF;
                END $$;
            """)

            # Verifica se a coluna anexos existe e tem o tipo correto
            cur.execute("""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'registros' AND column_name = 'anexos'
                        AND data_type != 'jsonb'
                    ) THEN
                        ALTER TABLE registros ALTER COLUMN anexos TYPE JSONB USING anexos::jsonb;
                        ALTER TABLE registros ALTER COLUMN anexos SET DEFAULT '[]'::jsonb;
                    END IF;
                END $$;
            """)
            
            # Verifica e adiciona a coluna direcionamentos se não existir
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'registros' AND column_name = 'direcionamentos'
                    ) THEN
                        ALTER TABLE registros ADD COLUMN direcionamentos TEXT;
                    END IF;
                END $$;
            """)
            
            # Verifica e adiciona a coluna local se não existir
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'registros' AND column_name = 'local'
                    ) THEN
                        ALTER TABLE registros ADD COLUMN local TEXT;
                    END IF;
                END $$;
            """)
            
            # Verifica e adiciona a coluna ultimo_editor se não existir
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'registros' AND column_name = 'ultimo_editor'
                    ) THEN
                        ALTER TABLE registros ADD COLUMN ultimo_editor TEXT;
                    END IF;
                END $$;
            """)
            
            # Verifica e adiciona a coluna data_ultima_edicao se não existir
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns 
                        WHERE table_name = 'registros' AND column_name = 'data_ultima_edicao'
                    ) THEN
                        ALTER TABLE registros ADD COLUMN data_ultima_edicao TIMESTAMP;
                    END IF;
                END $$;
            """)
            
            # Criando tabela de usuários
            print("Criando/verificando tabela 'users'...")
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    is_superuser BOOLEAN DEFAULT FALSE
                )
            ''')

            # Criando tabela de logs do sistema
            print("Criando/verificando tabela 'system_logs'...")
            cur.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id SERIAL PRIMARY KEY,
                    message TEXT NOT NULL,
                    level TEXT NOT NULL DEFAULT 'info',
                    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'America/Manaus')
                )
            ''')

            # Verifica se a tabela system_logs está vazia e adiciona um log inicial
            cur.execute('SELECT COUNT(*) FROM system_logs')
            if cur.fetchone()[0] == 0:
                cur.execute('''
                    INSERT INTO system_logs (message, level)
                    VALUES ('Sistema inicializado com sucesso', 'info')
                ''')

            # Criando tabela de configurações do sistema
            print("Criando/verificando tabela 'system_settings'...")
            cur.execute('''
                CREATE TABLE IF NOT EXISTS system_settings (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    per_page INTEGER NOT NULL DEFAULT 10,
                    session_timeout INTEGER NOT NULL DEFAULT 60,
                    auto_backup TEXT NOT NULL DEFAULT 'daily',
                    CONSTRAINT single_row CHECK (id = 1)
                )
            ''')
            
            # Verificando se as tabelas foram criadas
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
            tables = cur.fetchall()
            print("Tabelas existentes no banco:", [table[0] for table in tables])

            # Restaurando superadmin
            cur.execute("""
                INSERT INTO users (username, password, is_superuser)
                VALUES ('marcus', 'marcus123', true)
                ON CONFLICT (username) 
                DO UPDATE SET is_superuser = true, password = 'marcus123'
                WHERE users.username = 'marcus'
            """)
            
            db.commit()
            print("Banco de dados inicializado com sucesso!")
            
        except Exception as e:
            print(f"Erro ao inicializar banco de dados: {e}")
            raise
        finally:
            if 'db' in locals():
                db.close()
                print("Conexão com o banco de dados fechada.")

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

        # Processa os anexos
        anexos = []
        if 'files' in request.files:
            files = request.files.getlist('files')
            for file in files:
                if file and file.filename:
                    filename = save_file(file)
                    if filename:
                        anexo = {
                            'id': str(uuid.uuid4()),
                            'nome_original': secure_filename(file.filename),
                            'nome_arquivo': filename,
                            'data_upload': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'uploaded_by': current_user.username
                        }
                        anexos.append(anexo)

        # Insere o registro com os anexos
        query = '''
            INSERT INTO registros 
            (data, demanda, assunto, status, local, direcionamentos, ultimo_editor, data_ultima_edicao, anexos) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP AT TIME ZONE 'America/Manaus', %s)
        '''
        query_db(query, [
            data, demanda, assunto, status, local, direcionamentos, 
            current_user.username, json.dumps(anexos)
        ])
        
        flash('Registro salvo com sucesso!')
        return redirect(url_for('report'))

    except Exception as e:
        flash(f'Erro ao salvar o registro: {str(e)}')
        print(f'Erro ao salvar o registro: {str(e)}')
        return redirect(url_for('form'))

def get_sort_params():
    """Obtém e valida os parâmetros de ordenação"""
    valid_columns = ['data', 'demanda', 'assunto', 'local', 'status', 'data_registro', 'ultimo_editor', 'data_ultima_edicao']
    sort_column = request.args.get('sort', 'data_registro')
    sort_direction = request.args.get('direction', 'desc')
    
    if sort_column not in valid_columns:
        sort_column = 'data_registro'
    if sort_direction not in ['asc', 'desc']:
        sort_direction = 'desc'
        
    return sort_column, sort_direction

@app.route('/report', methods=['GET'])
@login_required
def report():
    try:
        # Parâmetros de paginação
        page = request.args.get('page', 1, type=int)
        per_page = 10
        offset = (page - 1) * per_page

        # Obtém parâmetros de ordenação
        sort_column, sort_direction = get_sort_params()

        # Obtém todos os filtros
        search_query = request.args.get('search', '').strip()
        data_inicial = request.args.get('data_inicial', '').strip()
        data_final = request.args.get('data_final', '').strip()
        periodo = request.args.get('periodo', '').strip()
        local_filter = request.args.get('local_filter', '').strip()
        status_filter = request.args.get('status_filter', '').strip()

        # Constrói a query base
        query = 'SELECT * FROM registros WHERE 1=1'
        count_query = 'SELECT COUNT(*) FROM registros WHERE 1=1'
        params = []

        # Adiciona condições conforme os filtros
        if search_query:
            condition = ' AND (demanda ILIKE %s OR assunto ILIKE %s)'
            query += condition
            count_query += condition
            params.extend(['%' + search_query + '%', '%' + search_query + '%'])
        
        # Processa filtros de data
        if periodo:
            hoje = datetime.now().date()
            if periodo == 'hoje':
                condition = ' AND data = %s'
                params.append(hoje)
            elif periodo == 'ontem':
                condition = ' AND data = %s'
                params.append(hoje - timedelta(days=1))
            elif periodo == 'semana':
                condition = ' AND data >= %s'
                params.append(hoje - timedelta(days=7))
            elif periodo == 'mes':
                condition = ' AND data >= %s'
                params.append(hoje - timedelta(days=30))
            elif periodo == 'trimestre':
                condition = ' AND data >= %s'
                params.append(hoje - timedelta(days=90))
            elif periodo == 'semestre':
                condition = ' AND data >= %s'
                params.append(hoje - timedelta(days=180))
            elif periodo == 'ano':
                condition = ' AND data >= %s'
                params.append(hoje - timedelta(days=365))
            query += condition
            count_query += condition
        else:
            if data_inicial:
                condition = ' AND data >= %s'
                query += condition
                count_query += condition
                params.append(data_inicial)
            if data_final:
                condition = ' AND data <= %s'
                query += condition
                count_query += condition
                params.append(data_final)
        
        filter_field = request.args.get('filter_field', '').strip()
        filter_value = request.args.get('filter_value', '').strip()
        
        if filter_field and filter_value:
            condition = f' AND {filter_field} ILIKE %s'
            query += condition
            count_query += condition
            params.append('%' + filter_value + '%')
        
        if status_filter:
            condition = ' AND status = %s'
            query += condition
            count_query += condition
            params.append(status_filter)

        # Obtém o total de registros para paginação
        total_registros = query_db(count_query, params, one=True)[0]
        total_pages = (total_registros + per_page - 1) // per_page

        # Adiciona ordenação e paginação
        query += f' ORDER BY {sort_column} {sort_direction}'
        query += ' LIMIT %s OFFSET %s'
        params.extend([per_page, offset])

        # Log para depuração
        print(f"Executando consulta: {query} com parâmetros: {params}")
        registros = query_db(query, params)
        
        return render_template('report.html',
                             registros=registros,
                             search_query=search_query,
                             current_page=page,
                             total_pages=total_pages,
                             sort_column=sort_column,
                             sort_direction=sort_direction)
    except Exception as e:
        flash(f'Erro ao carregar relatório: {str(e)}')
        return redirect(url_for('form'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    # Garante que a coluna anexos existe
    ensure_anexos_column()

    if request.method == 'POST':
        data = request.form.get('data', '').strip()
        demanda = request.form.get('demanda', '').strip()
        assunto = request.form.get('assunto', '').strip()
        status = request.form.get('status', '').strip()
        direcionamentos = request.form.get('direcionamentos', '').strip()

        if not all([data, demanda, assunto, status]):
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('edit', id=id))

        if status not in STATUS_CHOICES:
            flash('Por favor, selecione um status válido.')
            return redirect(url_for('edit', id=id))

        local = request.form.get('local', '').strip()
        
        if not all([data, demanda, assunto, status, local]):
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('edit', id=id))

        # Atualiza os dados básicos
        query = '''
            UPDATE registros 
            SET data = %s, demanda = %s, assunto = %s, status = %s, local = %s, direcionamentos = %s,
                ultimo_editor = %s, data_ultima_edicao = CURRENT_TIMESTAMP AT TIME ZONE 'America/Manaus'
            WHERE id = %s
        '''
        query_db(query, [data, demanda, assunto, status, local, direcionamentos, current_user.username, id])

        flash('Registro atualizado com sucesso!')
        return redirect(url_for('report'))

    # Busca o registro
    registro = query_db('''
        SELECT *, 
               COALESCE(anexos, '[]'::jsonb) as anexos 
        FROM registros 
        WHERE id = %s
    ''', [id], one=True)
    
    if not registro:
        flash('Registro não encontrado.')
        return redirect(url_for('report'))

    # Converte a string JSON para lista Python
    if isinstance(registro['anexos'], str):
        registro['anexos'] = json.loads(registro['anexos'])
    
    return render_template('edit.html', registro=registro, status_list=STATUS_CHOICES)

@app.route('/registro/<int:id>')
@login_required
def get_registro(id):
    try:
        # Garante que a coluna anexos existe
        ensure_anexos_column()
        
        registro = query_db('''
            SELECT *,
                   COALESCE(anexos, '[]'::jsonb) as anexos
            FROM registros 
            WHERE id = %s
        ''', [id], one=True)
        
        if registro:
            # Converte a string JSON para lista Python se necessário
            if isinstance(registro['anexos'], str):
                registro['anexos'] = json.loads(registro['anexos'])
                
            # Formata as datas para exibição
            return jsonify({
                'id': registro['id'],
                'data': registro['data'].strftime('%d/%m/%Y'),
                'demanda': registro['demanda'],
                'assunto': registro['assunto'],
                'local': registro['local'],
                'status': registro['status'],
                'data_registro': registro['data_registro'].strftime('%d/%m/%Y %H:%M'),
                'ultimo_editor': registro['ultimo_editor'],
                'data_ultima_edicao': registro['data_ultima_edicao'].strftime('%d/%m/%Y %H:%M') if registro['data_ultima_edicao'] else None,
                'anexos': registro['anexos']
            })
        return jsonify({'error': 'Registro não encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    try:
        query_db('DELETE FROM registros WHERE id = %s', [id])
        flash('Registro excluído com sucesso!')
    except Exception as e:
        flash(f'Erro ao excluir registro: {str(e)}')
    return redirect(url_for('report'))

def get_filtered_registros():
    """Função auxiliar para obter registros filtrados"""
    search_query = request.args.get('search', '').strip()
    data_filter = request.args.get('data_filter', '').strip()
    local_filter = request.args.get('local_filter', '').strip()
    status_filter = request.args.get('status_filter', '').strip()

    query = 'SELECT * FROM registros WHERE 1=1'
    params = []

    if search_query:
        query += ' AND (demanda ILIKE %s OR assunto ILIKE %s)'
        params.extend(['%' + search_query + '%', '%' + search_query + '%'])
    
    if data_filter:
        query += ' AND data = %s'
        params.append(data_filter)
    
    if local_filter:
        query += ' AND local ILIKE %s'
        params.append('%' + local_filter + '%')
    
    if status_filter:
        query += ' AND status = %s'
        params.append(status_filter)

    query += ' ORDER BY data_registro DESC'
    return query_db(query, params)

@app.route('/export/csv')
@login_required
def export_csv():
    try:
        registros = get_filtered_registros()
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['Data', 'Demanda', 'Assunto', 'Local', 'Direcionamentos', 'Status', 'Data de Registro', 'Último Editor', 'Data da Última Edição'])
        for registro in registros:
            data_ultima_edicao = registro['data_ultima_edicao'].strftime('%d/%m/%Y %H:%M') if registro['data_ultima_edicao'] else 'N/A'
            data_registro = registro['data_registro'].strftime('%d/%m/%Y %H:%M')
            cw.writerow([
                registro['data'],
                registro['demanda'],
                registro['assunto'],
                registro['local'] or 'N/A',
                registro['direcionamentos'] or 'N/A',
                registro['status'],
                data_registro,
                registro['ultimo_editor'] or 'N/A',
                data_ultima_edicao
            ])
        
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=relatorio.csv"
        output.headers["Content-type"] = "text/csv"
        return output
    except Exception as e:
        flash(f'Erro ao exportar dados: {str(e)}')
        return redirect(url_for('report'))

@app.route('/view_results')
@login_required
def view_results():
    try:
        registros = get_filtered_registros()
        return render_template('view_results.html', registros=registros)
    except Exception as e:
        flash(f'Erro ao carregar resultados: {str(e)}')
        return redirect(url_for('report'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            flash('Por favor, informe o nome de usuário.')
            return redirect(url_for('forgot_password'))
            
        user = query_db('SELECT * FROM users WHERE username = %s', [username], one=True)
        if user:
            # Gera uma senha temporária
            temp_password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))
            
            # Atualiza a senha no banco
            query_db('UPDATE users SET password = %s WHERE username = %s',
                    [temp_password, username])
            
            # Registra no log do sistema
            log_system_event(f'Senha resetada para o usuário: {username}')
            
            flash(f'Uma nova senha foi gerada: {temp_password}')
            return redirect(url_for('login'))
        else:
            flash('Usuário não encontrado.')
            return redirect(url_for('forgot_password'))
            
    return render_template('forgot_password.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_superuser:
        flash('Acesso negado. Você precisa ser um SuperUser.')
        return redirect(url_for('report'))
        
    # Obtém lista de usuários
    users = query_db('SELECT * FROM users ORDER BY username')
    
    # Obtém estatísticas
    stats = {
        'total_registros': query_db('SELECT COUNT(*) FROM registros', one=True)[0],
        'registros_hoje': query_db(
            'SELECT COUNT(*) FROM registros WHERE DATE(data_registro) = CURRENT_DATE',
            one=True
        )[0],
        'total_usuarios': query_db('SELECT COUNT(*) FROM users', one=True)[0],
        'registros_pendentes': query_db(
            'SELECT COUNT(*) FROM registros WHERE status = %s',
            ['Pendente'],
            one=True
        )[0],
        'status_counts': {}
    }
    
    # Contagem por status
    status_counts = query_db('''
        SELECT status, COUNT(*) as count 
        FROM registros 
        GROUP BY status
    ''')
    stats['status_counts'] = {row['status']: row['count'] for row in status_counts}
    
    # Obtém logs do sistema (últimos 50)
    try:
        system_logs = query_db('''
            SELECT message, level, created_at 
            FROM system_logs 
            ORDER BY created_at DESC 
            LIMIT 50
        ''')
        system_logs = [
            f"{log['created_at'].strftime('%d/%m/%Y %H:%M')} [{log['level']}] {log['message']}"
            for log in (system_logs or [])
        ]
    except Exception as e:
        print(f"Erro ao buscar logs: {e}")
        system_logs = ["Erro ao carregar logs do sistema"]
    
    # Obtém configurações atuais
    settings = query_db('SELECT * FROM system_settings', one=True) or DEFAULT_SETTINGS
    
    return render_template('admin.html',
                         users=users,
                         stats=stats,
                         system_logs=system_logs,
                         settings=settings)

@app.route('/admin/user/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    if not current_user.is_superuser:
        return jsonify({'error': 'Acesso negado'}), 403
        
    user = query_db('SELECT id, username, is_superuser FROM users WHERE id = %s', [user_id], one=True)
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'is_superuser': user['is_superuser']
        })
    return jsonify({'error': 'Usuário não encontrado'}), 404

@app.route('/admin/user/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    if not current_user.is_superuser:
        return jsonify({'error': 'Acesso negado'}), 403
        
    data = request.get_json()
    username = data.get('username', '').strip()
    is_superuser = data.get('is_superuser', False)
    new_password = data.get('password', '').strip()
    
    if not username:
        return jsonify({'error': 'Nome de usuário é obrigatório'}), 400
        
    try:
        # Verifica se o usuário existe
        user = query_db('SELECT * FROM users WHERE id = %s', [user_id], one=True)
        if not user:
            return jsonify({'error': 'Usuário não encontrado'}), 404
            
        # Verifica se o novo username já existe para outro usuário
        existing_user = query_db(
            'SELECT * FROM users WHERE username = %s AND id != %s', 
            [username, user_id], 
            one=True
        )
        if existing_user:
            return jsonify({'error': 'Nome de usuário já existe'}), 400
            
        # Constrói a query de atualização
        if new_password:
            query = '''
                UPDATE users 
                SET username = %s, is_superuser = %s, password = %s 
                WHERE id = %s
            '''
            params = [username, is_superuser, new_password, user_id]
            log_message = f'Usuário {username} atualizado (nome, permissões e senha)'
        else:
            query = '''
                UPDATE users 
                SET username = %s, is_superuser = %s 
                WHERE id = %s
            '''
            params = [username, is_superuser, user_id]
            log_message = f'Usuário {username} atualizado (nome e permissões)'
            
        # Executa a atualização
        query_db(query, params)
            
        # Registra no log do sistema
        log_system_event(log_message)
        
        return jsonify({
            'message': 'Usuário atualizado com sucesso',
            'user': {
                'id': user_id,
                'username': username,
                'is_superuser': is_superuser
            }
        })
    except Exception as e:
        log_system_event(f'Erro ao atualizar usuário: {str(e)}', 'error')
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_superuser:
        flash('Acesso negado.')
        return redirect(url_for('report'))
        
    if current_user.id == user_id:
        flash('Você não pode excluir seu próprio usuário.')
        return redirect(url_for('admin'))
        
    user = query_db('SELECT username FROM users WHERE id = %s', [user_id], one=True)
    if user:
        query_db('DELETE FROM users WHERE id = %s', [user_id])
        log_system_event(f'Usuário excluído: {user["username"]}')
        flash('Usuário excluído com sucesso!')
    else:
        flash('Usuário não encontrado.')
        
    return redirect(url_for('admin'))

@app.route('/admin/settings', methods=['POST'])
@login_required
def update_settings():
    if not current_user.is_superuser:
        flash('Acesso negado.')
        return redirect(url_for('report'))
        
    per_page = request.form.get('per_page', type=int)
    session_timeout = request.form.get('session_timeout', type=int)
    auto_backup = request.form.get('auto_backup')
    
    if per_page and session_timeout and auto_backup:
        query_db('''
            INSERT INTO system_settings (per_page, session_timeout, auto_backup)
            VALUES (%s, %s, %s)
            ON CONFLICT (id) DO UPDATE 
            SET per_page = EXCLUDED.per_page,
                session_timeout = EXCLUDED.session_timeout,
                auto_backup = EXCLUDED.auto_backup
        ''', [per_page, session_timeout, auto_backup])
        
        log_system_event('Configurações do sistema atualizadas')
        flash('Configurações atualizadas com sucesso!')
    else:
        flash('Por favor, preencha todos os campos.')
    
    return redirect(url_for('admin'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
