from flask import Flask
import fdb  # Importe o módulo fdb para Firebird
from models import Usuario, Profissional, Servico, Agenda, HorarioProfissional, Parametro  # Importe suas classes de modelo

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Configurações do banco de dados
host = app.config['DB_HOST']
database = app.config['DB_NAME']
user = app.config['DB_USER']
password = app.config['DB_PASSWORD']

# Conexão com o banco de dados
try:
    con = fdb.connect(
        host=host,
        database=database,
        user=user,
        password=password
    )
    print("Conexão estabelecida com sucesso!")

    # Fechar conexão ao finalizar o aplicativo
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        con.close()

except Exception as e:
    print(f"Erro ao conectar ao banco de dados: {e}")

# Importe as views após configurar o app e a conexão com o banco de dados
from views import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
