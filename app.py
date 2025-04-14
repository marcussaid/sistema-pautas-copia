from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import psycopg2
from psycopg2.extras import DictCursor
import os
import csv
import io
import time
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sistema_demandas_secret_key_2024')

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

def init_db():
    print("Iniciando configuração do banco de dados...")
    with app.app_context():
        try:
            db = get_db()
            cur = db.cursor()
            
            # Criando tabela de registros
            print("Criando/verificando tabela 'registros'...")
            cur.execute('''
                CREATE TABLE IF NOT EXISTS registros (
                    id SERIAL PRIMARY KEY,
                    data DATE NOT NULL,
                    demanda TEXT NOT NULL,
                    assunto TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ultimo_editor TEXT,
                    data_ultima_edicao TIMESTAMP
                )
            ''')
            
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
            
            # Verificando se as tabelas foram criadas
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
            tables = cur.fetchall()
            print("Tabelas existentes no banco:", [table[0] for table in tables])
            
            db.commit()
            print("Banco de dados inicializado com sucesso!")
            
        except Exception as e:
            print(f"Erro ao inicializar banco de dados: {e}")
            raise
        finally:
            if 'db' in locals():
                db.close()
                print("Conexão com o banco de dados fechada.")

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

        query = '''
            INSERT INTO registros 
            (data, demanda, assunto, status, ultimo_editor, data_ultima_edicao) 
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        '''
        query_db(query, [data, demanda, assunto, status, current_user.username])
        
        flash('Registro salvo com sucesso!')
        return redirect(url_for('report'))

    except Exception as e:
        flash(f'Erro ao salvar o registro: {str(e)}')
        print(f'Erro ao salvar o registro: {str(e)}')
        return redirect(url_for('form'))

@app.route('/report', methods=['GET'])
@login_required
def report():
    search_query = request.args.get('search', '').strip()
    try:
        if search_query:
            registros = query_db('SELECT * FROM registros WHERE demanda ILIKE %s OR assunto ILIKE %s ORDER BY data_registro DESC', 
                               ['%' + search_query + '%', '%' + search_query + '%'])
        else:
            registros = query_db('SELECT * FROM registros ORDER BY data_registro DESC')
        return render_template('report.html', registros=registros, search_query=search_query)
    except Exception as e:
        flash(f'Erro ao carregar relatório: {str(e)}')
        return redirect(url_for('form'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    if request.method == 'POST':
        data = request.form.get('data', '').strip()
        demanda = request.form.get('demanda', '').strip()
        assunto = request.form.get('assunto', '').strip()
        status = request.form.get('status', '').strip()

        if not all([data, demanda, assunto, status]):
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('edit', id=id))

        if status not in STATUS_CHOICES:
            flash('Por favor, selecione um status válido.')
            return redirect(url_for('edit', id=id))

        query = '''
            UPDATE registros 
            SET data = %s, demanda = %s, assunto = %s, status = %s, 
                ultimo_editor = %s, data_ultima_edicao = CURRENT_TIMESTAMP 
            WHERE id = %s
        '''
        query_db(query, [data, demanda, assunto, status, current_user.username, id])

        flash('Registro atualizado com sucesso!')
        return redirect(url_for('report'))

    registro = query_db('SELECT * FROM registros WHERE id = %s', [id], one=True)
    return render_template('edit.html', registro=registro, status_list=STATUS_CHOICES)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    try:
        query_db('DELETE FROM registros WHERE id = %s', [id])
        flash('Registro excluído com sucesso!')
    except Exception as e:
        flash(f'Erro ao excluir registro: {str(e)}')
    return redirect(url_for('report'))

@app.route('/export', methods=['GET'])
@login_required
def export():
    try:
        registros = query_db('SELECT * FROM registros ORDER BY data_registro DESC')
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['Data', 'Demanda', 'Assunto', 'Status', 'Data de Registro', 'Último Editor', 'Data da Última Edição'])
        for registro in registros:
            data_ultima_edicao = registro['data_ultima_edicao'].strftime('%d/%m/%Y %H:%M') if registro['data_ultima_edicao'] else 'N/A'
            data_registro = registro['data_registro'].strftime('%d/%m/%Y %H:%M')
            cw.writerow([
                registro['data'],
                registro['demanda'],
                registro['assunto'],
                registro['status'],
                data_registro,
                registro['ultimo_editor'] or 'N/A',
                data_ultima_edicao
            ])
        
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=registros.csv"
        output.headers["Content-type"] = "text/csv"
        return output
    except Exception as e:
        flash(f'Erro ao exportar dados: {str(e)}')
        return redirect(url_for('report'))

# Verifica a conexão com o banco de dados antes de iniciar
if not check_db_connection():
    print("ERRO: Não foi possível conectar ao banco de dados!")
    raise Exception("Falha na conexão com o banco de dados")

# Inicializa o banco de dados
init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
