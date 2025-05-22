import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import io
import json
import pytest
from app import app, query_db

import pytest
import io
import json
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, query_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with client.session_transaction() as sess:
            # Simula login manualmente na sessão
            user = query_db('SELECT * FROM users WHERE username = %s', ['admin'], one=True)
            if user:
                sess['user_id'] = user['id']
                sess['_fresh'] = True
                sess['_user_id'] = str(user['id'])
        yield client

def test_upload_and_download_and_delete_anexo(monkeypatch, client):
    # Mock boto3 S3 client upload_fileobj and delete_object to simulate S3 behavior
    class MockS3Client:
        def upload_fileobj(self, Fileobj, Bucket, Key):
            pass
        def delete_object(self, Bucket, Key):
            pass
        def download_fileobj(self, Bucket, Key, Fileobj):
            Fileobj.write(b"file content")
            Fileobj.seek(0)

    monkeypatch.setattr('boto3.client', lambda *args, **kwargs: MockS3Client())

    # Cria um registro temporário para testes
    query_db('INSERT INTO registros (data, demanda, assunto, status, local, direcionamentos, ultimo_editor, data_ultima_edicao) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)', 
             ['2024-01-01', 'Demanda Teste', 'Assunto Teste', 'Pendente', 'Local Teste', 'Direcionamentos Teste', 'admin'])
    registro = query_db('SELECT id FROM registros WHERE demanda = ? AND assunto = ?', ['Demanda Teste', 'Assunto Teste'], one=True)
    registro_id = registro['id'] if registro else 1

    # Upload do anexo
    data = {
        'file': (io.BytesIO(b"file content"), 'test.txt')
    }
    headers = {
        'Authorization': 'Bearer test-token'
    }
    response = client.post(f'/upload_anexo/{registro_id}', data=data, content_type='multipart/form-data', headers=headers)
    json_data = json.loads(response.data)
    assert response.status_code == 200
    assert json_data['success'] is True
    assert 'anexo' in json_data
    anexo_id = json_data['anexo']['id']

    # Download do anexo
    response = client.get(f'/download_anexo/{registro_id}/{anexo_id}', headers=headers)
    assert response.status_code == 200
    assert response.data == b"file content"

    # Exclusão do anexo
    response = client.delete(f'/delete_anexo/{registro_id}/{anexo_id}', headers=headers)
    json_data = json.loads(response.data)
    assert response.status_code == 200
    assert json_data['success'] is True

    # Remove o registro após o teste
    query_db('DELETE FROM registros WHERE id = ?', [registro_id])
