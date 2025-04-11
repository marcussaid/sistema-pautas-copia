# Sistema de Registro de Demandas

Sistema web para registro e acompanhamento de demandas desenvolvido com Flask.

## Funcionalidades

- Registro de demandas com data, descrição, assunto e status
- Visualização de demandas em formato de relatório
- Banco de dados persistente
- Interface responsiva com Tailwind CSS

## Requisitos

- Python 3.8+
- Flask
- PostgreSQL (produção) ou SQLite (desenvolvimento)

## Configuração Local

1. Clone o repositório:
```bash
git clone https://github.com/marcussaid/sistema-pautas.git
cd sistema-pautas
```

2. Crie um ambiente virtual e ative-o:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Execute a aplicação:
```bash
python app.py
```

A aplicação estará disponível em `http://localhost:8000`

## Implantação no Render.com

1. Crie uma conta no [Render.com](https://render.com)

2. Crie um novo Web Service:
   - Conecte ao repositório https://github.com/marcussaid/sistema-pautas.git
   - Selecione a branch principal
   - Selecione "Python" como ambiente
   - Configure o comando de build: `pip install -r requirements.txt`
   - Configure o comando de start: `gunicorn app:app`

3. Configure as variáveis de ambiente:
   - `DATABASE_URL`: URL de conexão do PostgreSQL
   - `SECRET_KEY`: Chave secreta para a aplicação Flask

4. Clique em "Create Web Service"

## Variáveis de Ambiente

- `DATABASE_URL`: URL de conexão do banco de dados (PostgreSQL em produção, SQLite em desenvolvimento)
- `SECRET_KEY`: Chave secreta para a aplicação Flask
- `PORT`: Porta para executar a aplicação (opcional, padrão: 8000)

## Estrutura do Projeto

```
.
├── app.py              # Aplicação principal
├── requirements.txt    # Dependências do projeto
├── Procfile           # Configuração para o Render.com
├── .gitignore         # Arquivos ignorados pelo Git
└── templates/         # Templates HTML
    ├── base.html      # Template base
    ├── form.html      # Formulário de registro
    └── report.html    # Relatório de demandas
```

## Desenvolvimento

Para desenvolvimento local, a aplicação usa SQLite por padrão. Para usar PostgreSQL localmente, configure a variável de ambiente `DATABASE_URL` com a URL de conexão do PostgreSQL.

## Contribuindo

1. Faça um Fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

MIT
