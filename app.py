from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
import sqlite3
import os
import csv
import io
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sua_chave_secreta')

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configuração do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
mail = Mail(app)

# Lista de status disponíveis
STATUS_CHOICES = ['Em andamento', 'Concluído', 'Pendente', 'Cancelado']

# Configuração do banco de dados
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///database.db')

class User(UserMixin):
    def __init__(self, id, email=None):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    user = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    if user:
        return User(user['id'], user['email'])
    return None

def get_db():
    if DATABASE_URL.startswith('sqlite'):
        db = sqlite3.connect('database.db')
        db.row_factory = sqlite3.Row
    else:
        import psycopg2
        from psycopg2.extras import DictCursor
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        db = conn
        db.row_factory = DictCursor
    return db

def init_db():
    with app.app_context():
        db = get_db()
        try:
            db.execute('''
                CREATE TABLE IF NOT EXISTS registros (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    data DATE NOT NULL,
                    demanda TEXT NOT NULL,
                    assunto TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE
                )
            ''')
            db.commit()
        except Exception as e:
            print(f"Erro ao criar tabela: {e}")
        finally:
            db.close()

def query_db(query, args=(), one=False):
    db = get_db()
    try:
        if DATABASE_URL.startswith('sqlite'):
            cur = db.execute(query, args)
            rv = cur.fetchall()
            db.commit()
            return (rv[0] if rv else None) if one else rv
        else:
            cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute(query, args)
            rv = cur.fetchall()
            cur.close()
            return (rv[0] if rv else None) if one else rv
    finally:
        if hasattr(db, 'close'):
            db.close()

def send_notification(email, demanda, status):
    try:
        msg = Message('Atualização de Demanda',
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[email])
        msg.body = f'A demanda "{demanda}" teve seu status atualizado para "{status}".'
        mail.send(msg)
    except Exception as e:
        print(f"Erro ao enviar notificação: {e}")

@app.route('/')
def index():
    return redirect(url_for('form'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = query_db('SELECT * FROM users WHERE username = ? AND password = ?',
                       [username, password], one=True)
        if user:
            login_user(User(user['id'], user['email']))
            return redirect(url_for('form'))
        flash('Usuário ou senha inválidos.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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

        if DATABASE_URL.startswith('sqlite'):
            query = 'INSERT INTO registros (data, demanda, assunto, status) VALUES (?, ?, ?, ?)'
        else:
            query = 'INSERT INTO registros (data, demanda, assunto, status) VALUES (%s, %s, %s, %s)'
        
        query_db(query, [data, demanda, assunto, status])
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
            registros = query_db('SELECT * FROM registros WHERE demanda LIKE ? OR assunto LIKE ? ORDER BY data_registro DESC', 
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

        old_status = query_db('SELECT status FROM registros WHERE id = ?', [id], one=True)['status']
        if old_status != status and current_user.email:
            send_notification(current_user.email, demanda, status)

        if DATABASE_URL.startswith('sqlite'):
            query = 'UPDATE registros SET data = ?, demanda = ?, assunto = ?, status = ? WHERE id = ?'
            query_db(query, [data, demanda, assunto, status, id])
        else:
            query = 'UPDATE registros SET data = %s, demanda = %s, assunto = %s, status = %s WHERE id = %s'
            query_db(query, [data, demanda, assunto, status, id])

        flash('Registro atualizado com sucesso!')
        return redirect(url_for('report'))

    registro = query_db('SELECT * FROM registros WHERE id = ?', [id], one=True)
    return render_template('edit.html', registro=registro, status_list=STATUS_CHOICES)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    try:
        if DATABASE_URL.startswith('sqlite'):
            query_db('DELETE FROM registros WHERE id = ?', [id])
        else:
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
        cw.writerow(['Data', 'Demanda', 'Assunto', 'Status', 'Data de Registro'])
        for registro in registros:
            cw.writerow([registro['data'], registro['demanda'], registro['assunto'], 
                        registro['status'], registro['data_registro']])
        
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=registros.csv"
        output.headers["Content-type"] = "text/csv"
        return output
    except Exception as e:
        flash(f'Erro ao exportar dados: {str(e)}')
        return redirect(url_for('report'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
