import io
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, query_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        # Simula login para acessar rotas protegidas
        login_data = {
            'username': 'admin',
            'password': 'admin'
        }
        client.post('/login', data=login_data)
        
        # Cria um registro temporário para testes
        query_db('INSERT INTO registros (data, demanda, assunto, status, local, direcionamentos, ultimo_editor, data_ultima_edicao) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)', 
                 ['2024-01-01', 'Demanda Teste', 'Assunto Teste', 'Pendente', 'Local Teste', 'Direcionamentos Teste', 'admin'])
        # Obtém o id do registro criado
        registro = query_db('SELECT id FROM registros WHERE demanda = ? AND assunto = ?', ['Demanda Teste', 'Assunto Teste'], one=True)
        registro_id = registro['id'] if registro else 1
        
        # Armazena o id para uso nos testes
        client.registro_id = registro_id
        
        yield client
        
        # Remove o registro após os testes
        query_db('DELETE FROM registros WHERE id = ?', [registro_id])

def test_upload_valid_file(monkeypatch, client):
    # Mock boto3 S3 client upload_fileobj to simulate successful upload
    class MockS3Client:
        def upload_fileobj(self, Fileobj, Bucket, Key):
            pass

    monkeypatch.setattr('boto3.client', lambda *args, **kwargs: MockS3Client())

    data = {
        'file': (io.BytesIO(b"file content"), 'test.txt')
    }
    response = client.post(f'/upload_anexo/{client.registro_id}', data=data, content_type='multipart/form-data')
    json_data = json.loads(response.data)
    assert response.status_code == 200
    assert json_data['success'] is True
    assert 'anexo' in json_data
    assert json_data['anexo']['nome_original'] == 'test.txt'

def test_upload_no_file(client):
    response = client.post(f'/upload_anexo/{client.registro_id}', data={}, content_type='multipart/form-data')
    json_data = json.loads(response.data)
    assert response.status_code == 400
    assert 'error' in json_data

def test_upload_empty_file(client):
    data = {
        'file': (io.BytesIO(b""), '')
    }
    response = client.post(f'/upload_anexo/{client.registro_id}', data=data, content_type='multipart/form-data')
    json_data = json.loads(response.data)
    assert response.status_code == 400
    assert 'error' in json_data
