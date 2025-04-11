from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sua_chave_secreta')

# Lista de status disponíveis
STATUS_CHOICES = ['Em andamento', 'Concluído', 'Pendente', 'Cancelado']

# Configuração do banco de dados
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///database.db')

def get_db():
    if DATABASE_URL.startswith('sqlite'):
        db = sqlite3.connect('database.db')
        db.row_factory = sqlite3.Row
    else:
        # Se estiver usando PostgreSQL em produção
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
            if DATABASE_URL.startswith('sqlite'):
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
            else:
                # PostgreSQL
                db.cursor().execute('''
                    CREATE TABLE IF NOT EXISTS registros (
                        id SERIAL PRIMARY KEY,
                        data DATE NOT NULL,
                        demanda TEXT NOT NULL,
                        assunto TEXT NOT NULL,
                        status TEXT NOT NULL,
                        data_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
            if hasattr(db, 'commit'):
                db.commit()
        except Exception as e:
            print(f"Erro ao criar tabela: {e}")
        finally:
            if hasattr(db, 'close'):
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
            # PostgreSQL
            cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute(query, args)
            rv = cur.fetchall()
            cur.close()
            return (rv[0] if rv else None) if one else rv
    finally:
        if hasattr(db, 'close'):
            db.close()

@app.route('/')
def index():
    return redirect(url_for('form'))

@app.route('/form', methods=['GET'])
def form():
    today = datetime.now().strftime('%Y-%m-%d')
    return render_template('form.html', 
                         status_list=STATUS_CHOICES,
                         form_data=request.form,
                         today=today)

@app.route('/submit', methods=['POST'])
def submit():
    try:
        data = request.form.get('data', '').strip()
        demanda = request.form.get('demanda', '').strip()
        assunto = request.form.get('assunto', '').strip()
        status = request.form.get('status', '').strip()

        # Validação dos campos
        if not all([data, demanda, assunto, status]):
            flash('Por favor, preencha todos os campos.')
            return redirect(url_for('form'))

        if status not in STATUS_CHOICES:
            flash('Por favor, selecione um status válido.')
            return redirect(url_for('form'))

        # Inserir no banco de dados
        if DATABASE_URL.startswith('sqlite'):
            query = 'INSERT INTO registros (data, demanda, assunto, status) VALUES (?, ?, ?, ?)'
        else:
            query = 'INSERT INTO registros (data, demanda, assunto, status) VALUES (%s, %s, %s, %s)'
        
        query_db(query, [data, demanda, assunto, status])

        flash('Registro salvo com sucesso!')
        return redirect(url_for('report'))

    except Exception as e:
        flash(f'Erro ao salvar o registro: {str(e)}')
        print(f'Erro ao salvar o registro: {str(e)}')  # Log detalhado
        return redirect(url_for('form'))

@app.route('/report', methods=['GET'])
def report():
    try:
        registros = query_db('SELECT * FROM registros ORDER BY data_registro DESC')
        return render_template('report.html', registros=registros)
    except Exception as e:
        flash(f'Erro ao carregar relatório: {str(e)}')
        return redirect(url_for('form'))

@app.route('/delete/<int:id>', methods=['POST'])
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

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
