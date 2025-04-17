@echo off
echo Configurando Git para nao usar paginacao...
set GIT_PAGER=

echo Verificando o status atual...
git status

echo Adicionando app.py...
git add app.py
git commit -m "Adiciona rotas ausentes e funcionalidade de atualizacao via AJAX"

echo Adicionando base.html...
git add templates/base.html
git commit -m "Corrige exibicao de menu na pagina de login"

echo Adicionando templates de autenticacao...
git add templates/login.html templates/register.html templates/forgot_password.html
git commit -m "Adiciona botao de alternar tema nas paginas de autenticacao"

echo Adicionando report.html...
git add templates/report.html
git commit -m "Integra pesquisa avancada ao relatorio e adiciona contador de registros"

echo Verificando status final...
git status

echo Commits concluidos com sucesso!
pause 