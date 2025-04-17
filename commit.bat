@echo off
git add app.py
git commit -m "Adiciona rotas ausentes e funcionalidade de atualizacao via AJAX"

git add templates/base.html
git commit -m "Corrige exibicao de menu na pagina de login"

git add templates/login.html templates/register.html templates/forgot_password.html
git commit -m "Adiciona botao de alternar tema nas paginas de autenticacao"

git add templates/report.html
git commit -m "Integra pesquisa avancada ao relatorio e adiciona contador de registros"

echo Commits concluidos com sucesso! 