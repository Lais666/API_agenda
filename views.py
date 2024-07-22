from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import fdb
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from models import Cliente, Profissional, Servico, Agenda, HorarioProfissional, Parametro, ProfissionalServico
import jwt
from functools import wraps
from datetime import datetime, timedelta, time
from werkzeug.utils import secure_filename
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'  # Diretório onde as imagens serão salvas
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
bcrypt = Bcrypt(app)

# Conexão com o banco de dados
try:
    con = fdb.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    print("Conexão estabelecida com sucesso!")
except Exception as e:
    print(f"Erro ao conectar ao banco de dados: {e}")

def gerar_token(cliente_id):
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'sub': cliente_id
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
def remover_prefixo_bearer(token):
    if token.startswith('Bearer '):
        return token[7:]
    return token


def validar_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'message': 'Token ausente!'}), 401

        try:
            token = remover_prefixo_bearer(token)
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = payload['sub']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido!', "token": token}), 401

        return f(*args, **kwargs, current_user=current_user)

    return decorated_function


def profissional_disponivel(id_profissional, data_hora, id_servico):
    try:
        cursor = con.cursor()

        # Chamada do procedimento armazenado
        cursor.callproc('VERIFICARHORARIODISPONIVEL', (id_profissional, data_hora, id_servico))
        resultado = cursor.fetchone()

        if resultado:
            disponivel = resultado[0]
            return disponivel

        return False  # Caso não encontre resultado

    except Exception as e:
        print(f"Erro ao verificar disponibilidade: {e}")
        return False

    finally:
        cursor.close()


def validar_senha(senha):
    if len(senha) < 8:
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_caractere_especial = False
    caracteres_especiais = "!@#$%^&*(),.?\":{}|<>"

    for char in senha:
        if char.isupper():
            tem_maiuscula = True
        elif char.islower():
            tem_minuscula = True
        elif char.isdigit():
            tem_numero = True
        elif char in caracteres_especiais:
            tem_caractere_especial = True

    return tem_maiuscula and tem_minuscula and tem_numero and tem_caractere_especial


def obter_profissionais_disponiveis(data_hora, id_servico):
    try:
        cursor = con.cursor()

        # Consulta SQL para encontrar profissionais disponíveis
        cursor.execute("""
            SELECT p.ID_PROFISSIONAL
            FROM PROFISSIONAL p
            WHERE NOT EXISTS (
                SELECT 1
                FROM AGENDA a
                WHERE a.ID_PROFISSIONAL = p.ID_PROFISSIONAL
                AND a.DATA_HORA = ?
            )
            AND p.ID_PROFISSIONAL IN (
                SELECT ps.ID_PROFISSIONAL
                FROM PROFISSIONAL_SERVICO ps
                WHERE ps.ID_SERVICO = ?
            )
        """, (data_hora, id_servico))

        resultados = cursor.fetchall()
        profissionais = [row[0] for row in resultados]  # Extraí os IDs dos profissionais

        return profissionais
    except Exception as e:
        print(f"Erro ao obter profissionais disponíveis: {e}")
        return []
    finally:
        cursor.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']



# Rotas para Cliente (exemplo)
@app.route('/clientes', methods=['GET'])
@validar_token
def get_clientes(current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM CLIENTE")
        clientes = cursor.fetchall()

        output = []
        for cliente in clientes:
            id_cliente, nome, email, telefone, ativo, tentativas_login, senha = cliente
            cliente_data = {
                'id_cliente': id_cliente,
                'nome': nome,
                'email': email,
                'telefone': telefone
                # senha não deve ser retornada para segurança
            }
            output.append(cliente_data)

        return jsonify({'clientes': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/cliente/<int:id_cliente>', methods=['GET'])
@validar_token
def get_cliente(id_cliente, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM CLIENTE WHERE ID_CLIENTE=?", (id_cliente,))
        cliente = cursor.fetchone()

        if not cliente:
            return jsonify({'message': 'Cliente não encontrado'}), 404

        id_cliente, nome, email, telefone, ativo, tentativas_login, senha = cliente
        cliente_data = {
            'id_cliente': id_cliente,
            'nome': nome,
            'email': email,
            'telefone': telefone
            # senha não deve ser retornada para segurança
        }
        return jsonify(cliente_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/cliente', methods=['POST'])
def create_cliente():
    data = request.get_json()
    # Valida a senha
    if not validar_senha(data['senha']):
        return jsonify({
                           'error': 'Senha inválida. A senha deve ter pelo menos 8 caracteres e incluir uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 400

    hashed_password = bcrypt.generate_password_hash(data['senha']).decode('utf-8')
    tentativas_login = data.get('tentativas_login', 0)
    try:
        cursor = con.cursor()
        cursor.execute("INSERT INTO CLIENTE (NOME, EMAIL, TELEFONE, ATIVO , TENTATIVAS_LOGIN, SENHA) VALUES (?, ?, ?, ?, ?, ?)",
                       (data['nome'], data['email'], data['telefone'], data['ativo'], tentativas_login, hashed_password))
        con.commit()

        return jsonify({'message': 'Novo cliente criado com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
@app.route('/cliente/<int:id_cliente>', methods=['PUT'])
def update_cliente(id_cliente):
    data = request.get_json()

    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM CLIENTE WHERE ID_CLIENTE=?", (id_cliente,))
        cliente = cursor.fetchone()

        if not cliente:
            return jsonify({'message': 'Cliente não encontrado'}), 404

        cursor.execute("UPDATE CLIENTE SET NOME=?, EMAIL=?, TELEFONE=?, ATIVO=? WHERE ID_CLIENTE=?",
                       (data['nome'], data['email'], data['telefone'], data['ativo'], id_cliente))
        con.commit()

        return jsonify({'message': 'Cliente atualizado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/cliente/login', methods=['POST'])
def login_cliente():
    auth_data = request.get_json()
    email = auth_data.get('email')
    senha = auth_data.get('senha')

    if not email or not senha:
        return jsonify({'error': 'Email e senha são obrigatórios.'}), 400

    cursor = None
    try:
        cursor = con.cursor()
        cursor.execute("SELECT ID_CLIENTE, SENHA, TENTATIVAS_LOGIN, ATIVO FROM CLIENTE WHERE EMAIL=?", (email,))
        cliente = cursor.fetchone()

        if cliente:
            id_cliente, senha_hash, tentativas_login, ativo = cliente

            if ativo == 0:
                return jsonify({'error': 'Conta inativa. Entre em contato com o suporte.'}), 403

            if bcrypt.check_password_hash(senha_hash, senha):
                # Resetar tentativas de login em caso de sucesso
                cursor.execute("UPDATE CLIENTE SET TENTATIVAS_LOGIN = 0 WHERE ID_CLIENTE=?", (id_cliente,))
                con.commit()
                token = gerar_token(id_cliente)
                return jsonify({'message': 'Login bem-sucedido!', 'token': token}), 200
            else:
                # Incrementar contagem de tentativas falhas
                tentativas_login += 1
                if tentativas_login >= 3:
                    cursor.execute("UPDATE CLIENTE SET ATIVO = false, TENTATIVAS_LOGIN = ? WHERE ID_CLIENTE=?",
                                   (tentativas_login, id_cliente))
                    con.commit()
                    return jsonify({'error': 'Número máximo de tentativas de login excedido. Sua conta foi desativada.'}), 403
                else:
                    cursor.execute("UPDATE CLIENTE SET TENTATIVAS_LOGIN = ? WHERE ID_CLIENTE=?",
                                   (tentativas_login, id_cliente))
                    con.commit()
                    return jsonify({'error': 'Senha incorreta. Tente novamente.'}), 401
        else:
            return jsonify({'error': 'Email não encontrado.'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()

@app.route('/profissionais', methods=['GET'])
@validar_token
def get_profissionais(current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM PROFISSIONAL")
        profissionais = cursor.fetchall()

        output = []
        for profissional in profissionais:
            id_profissional, nome, telefone, ativo = profissional
            profissional_data = {
                'id_profissional': id_profissional,
                'nome': nome,
                'telefone': telefone
            }
            output.append(profissional_data)

        return jsonify({'profissionais': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()


@app.route('/profissionais/disponiveis', methods=['GET'])
@validar_token
def get_profissionais_disponiveis(current_user):
    # Obtemos os parâmetros de data, hora e serviço da query string
    data_hora = request.args.get('data_hora')
    id_servico = request.args.get('id_servico')

    if not data_hora or not id_servico:
        return jsonify({'error': 'Parâmetros de data_hora e id_servico são obrigatórios.'}), 400

    try:
        # Converte data_hora para o formato esperado (ajuste conforme necessário)
        data_hora = datetime.strptime(data_hora, '%Y-%m-%dT%H:%M:%S')

        # Função para obter IDs dos profissionais disponíveis
        profissionais_disponiveis = obter_profissionais_disponiveis(data_hora, id_servico)

        return jsonify({'profissionais_disponiveis': profissionais_disponiveis})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/profissional/<int:id_profissional>', methods=['GET'])
@validar_token
def get_profissional(id_profissional, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM PROFISSIONAL WHERE ID_PROFISSIONAL=?", (id_profissional,))
        profissional = cursor.fetchone()

        if not profissional:
            return jsonify({'message': 'Profissional não encontrado'}), 404

        id_profissional, nome, telefone, ativo = profissional
        profissional_data = {
            'id_profissional': id_profissional,
            'nome': nome,
            'telefone': telefone
        }
        return jsonify(profissional_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional', methods=['POST'])
@validar_token
def create_profissional(current_user):
    data = request.get_json()

    try:
        cursor = con.cursor()
        cursor.execute("INSERT INTO PROFISSIONAL (NOME, TELEFONE, ATIVO) VALUES (?, ?, ?)",
                       (data['nome'], data['telefone'], data['ativo']))
        con.commit()

        return jsonify({'message': 'Novo profissional criado com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional/<int:id_profissional>', methods=['PUT'])
@validar_token
def update_profissional(id_profissional, current_user):
    data = request.get_json()

    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM PROFISSIONAL WHERE ID_PROFISSIONAL=?", (id_profissional,))
        profissional = cursor.fetchone()

        if not profissional:
            return jsonify({'message': 'Profissional não encontrado'}), 404

        cursor.execute("UPDATE PROFISSIONAL SET NOME=?, TELEFONE=? ATIVO=? WHERE ID_PROFISSIONAL=?",
                       (data['nome'], data['telefone'], data['ativo'], id_profissional))
        con.commit()

        return jsonify({'message': 'Profissional atualizado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional/<int:id_profissional>', methods=['DELETE'])
@validar_token
def delete_profissional(id_profissional, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM PROFISSIONAL WHERE ID_PROFISSIONAL=?", (id_profissional,))
        profissional = cursor.fetchone()

        if not profissional:
            return jsonify({'message': 'Profissional não encontrado'}), 404

        cursor.execute("DELETE FROM PROFISSIONAL WHERE ID_PROFISSIONAL=?", (id_profissional,))
        con.commit()

        return jsonify({'message': 'Profissional excluído com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

# Rotas para Serviço
@app.route('/servicos', methods=['GET'])
@validar_token
def get_servicos(current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM SERVICO")
        servicos = cursor.fetchall()

        output = []
        for servico in servicos:
            id_servico, nome, descricao, valor, tempo = servico

            # Converter o tempo para string no formato HH:MM:SS
            if tempo and isinstance(tempo, time):
                tempo_str = tempo.strftime('%H:%M:%S')
            else:
                tempo_str = tempo  # Pode ser uma string ou None

            servico_data = {
                'id_servico': id_servico,
                'nome': nome,
                'descricao': descricao,
                'valor': valor,
                'tempo': tempo_str
            }
            output.append(servico_data)

        return jsonify({'servicos': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/servico/<int:id_servico>', methods=['GET'])
@validar_token
def get_servico(id_servico, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM SERVICO WHERE ID_SERVICO=?", (id_servico,))
        servico = cursor.fetchone()

        if not servico:
            return jsonify({'message': 'Serviço não encontrado'}), 404

        id_servico, nome, descricao, valor, tempo = servico
        # Converter o tempo para string no formato HH:MM:SS
        if tempo and isinstance(tempo, time):
            tempo_str = tempo.strftime('%H:%M:%S')
        else:
            tempo_str = tempo  # Pode ser uma string ou None

        servico_data = {
            'id_servico': id_servico,
            'nome': nome,
            'descricao': descricao,
            'valor': valor,
            'tempo': tempo_str
        }
        return jsonify(servico_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()


@app.route('/servico', methods=['POST'])
def create_servico():
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nenhum arquivo selecionado'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Tipo de arquivo não permitido'}), 400

    # Obter dados adicionais do serviço
    data = request.form.to_dict()
    nome = data.get('nome')
    descricao = data.get('descricao')
    valor = data.get('valor')

    try:
        cursor = con.cursor()

        # Inserir dados do serviço no banco
        cursor.execute("""
            INSERT INTO SERVICO (NOME, DESCRICAO, VALOR) 
            VALUES (?, ?, ?)
        """, (nome, descricao, valor))
        con.commit()

        # Obter o ID do serviço inserido
        id_servico = cursor.lastrowid

        # Salvar o arquivo com o ID do serviço
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        filename = f"servico_{id_servico}.{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        return jsonify({'message': 'Serviço criado com sucesso!', 'file_path': file_path}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/servico/<int:id_servico>', methods=['PUT'])
@validar_token
def update_servico(id_servico, current_user):
    data = request.get_json()

    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM SERVICO WHERE ID_SERVICO=?", (id_servico,))
        servico = cursor.fetchone()

        if not servico:
            return jsonify({'message': 'Serviço não encontrado'}), 404

        cursor.execute("UPDATE SERVICO SET NOME=?, DESCRICAO=?, VALOR=?, TEMPO=?, ATIVO=? WHERE ID_SERVICO=?",
                       (data['nome'], data['descricao'], data['valor'], data['tempo'], data['ativo'], id_servico))
        con.commit()

        return jsonify({'message': 'Serviço atualizado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/servico/<int:id_servico>', methods=['DELETE'])
@validar_token
def delete_servico(id_servico, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM SERVICO WHERE ID_SERVICO=?", (id_servico,))
        servico = cursor.fetchone()

        if not servico:
            return jsonify({'message': 'Serviço não encontrado'}), 404

        cursor.execute("DELETE FROM SERVICO WHERE ID_SERVICO=?", (id_servico,))
        con.commit()

        return jsonify({'message': 'Serviço excluído com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

# Rotas para Agenda (exemplo de implementação)
@app.route('/agendas', methods=['GET'])
@validar_token
def get_agendas(current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM AGENDA")
        agendas = cursor.fetchall()

        output = []
        for agenda in agendas:
            id_agenda, id_cliente, id_profissional, id_servico, data_hora, status = agenda
            agenda_data = {
                'id_agenda': id_agenda,
                'id_cliente': id_cliente,
                'id_profissional': id_profissional,
                'id_servico': id_servico,
                'data_hora': data_hora.strftime('%Y-%m-%d %H:%M:%S'),
                'status': status
            }
            output.append(agenda_data)

        return jsonify({'agendas': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/agenda/<int:id_agenda>', methods=['GET'])
@validar_token
def get_agenda(id_agenda, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM AGENDA WHERE ID_AGENDA=?", (id_agenda,))
        agenda = cursor.fetchone()

        if not agenda:
            return jsonify({'message': 'Agenda não encontrada'}), 404

        id_agenda, id_cliente, id_profissional, id_servico, data_hora, status = agenda
        agenda_data = {
            'id_agenda': id_agenda,
            'id_cliente': id_cliente,
            'id_profissional': id_profissional,
            'id_servico': id_servico,
            'data_hora': data_hora.strftime('%Y-%m-%d %H:%M:%S'),
            'status': status
        }
        return jsonify(agenda_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
@app.route('/agenda', methods=['POST'])
@validar_token
def create_agenda(current_user):
    data = request.get_json()

    # Converter data_hora para datetime
    data_hora = datetime.strptime(data['data_hora'], '%Y-%m-%d %H:%M:%S')

    # Verificar disponibilidade do profissional
    if not profissional_disponivel(data['id_profissional'], data_hora, data['id_servico']):
        return jsonify({'message': 'Profissional não está disponível neste horário'}), 400

    try:
        cursor = con.cursor()
        cursor.execute("""
            INSERT INTO AGENDA (ID_CLIENTE, ID_PROFISSIONAL, ID_SERVICO, DATA_HORA, STATUS) 
            VALUES (?, ?, ?, ?, ?)
        """, (
            data['id_cliente'],
            data['id_profissional'],
            data['id_servico'],
            data_hora,  # Certifique-se de que data_hora seja um objeto datetime
            data['status']
        ))
        con.commit()

        return jsonify({'message': 'Nova agenda criada com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/agenda/<int:id_agenda>', methods=['PUT'])
@validar_token
def update_agenda(id_agenda, current_user):
    data = request.get_json()

    # Converter data_hora para datetime
    data_hora = datetime.strptime(data['data_hora'], '%Y-%m-%d %H:%M:%S')

    # Verificar disponibilidade do profissional
    if not profissional_disponivel(data['id_profissional'], data_hora, data['id_servico']):
        return jsonify({'message': 'Profissional não está disponível neste horário'}), 400

    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM AGENDA WHERE ID_AGENDA=?", (id_agenda,))
        agenda = cursor.fetchone()

        if not agenda:
            return jsonify({'message': 'Agenda não encontrada'}), 404

        cursor.execute("""
            UPDATE AGENDA 
            SET ID_CLIENTE=?, ID_PROFISSIONAL=?, ID_SERVICO=?, DATA_HORA=?, STATUS=? 
            WHERE ID_AGENDA=?
        """, (
            data['id_cliente'],
            data['id_profissional'],
            data['id_servico'],
            data_hora,  # Certifique-se de que data_hora seja um objeto datetime
            data['status'],
            id_agenda
        ))
        con.commit()

        return jsonify({'message': 'Agenda atualizada com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
@app.route('/agenda/<int:id_agenda>', methods=['DELETE'])
@validar_token
def delete_agenda(id_agenda, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM AGENDA WHERE ID_AGENDA=?", (id_agenda,))
        agenda = cursor.fetchone()

        if not agenda:
            return jsonify({'message': 'Agenda não encontrada'}), 404

        cursor.execute("DELETE FROM AGENDA WHERE ID_AGENDA=?", (id_agenda,))
        con.commit()

        return jsonify({'message': 'Agenda excluída com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()



# Rota para manipulação da tabela PROFISSIONAL_SERVICO
@app.route('/profissional_servico', methods=['GET'])
@validar_token
def get_profissional_servico(current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM PROFISSIONAL_SERVICO")
        profissional_servico = cursor.fetchall()

        output = []
        for ps in profissional_servico:
            id_profissional, id_servico = ps
            profissional_servico_data = {
                'id_profissional': id_profissional,
                'id_servico': id_servico
            }
            output.append(profissional_servico_data)

        return jsonify({'profissional_servico': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional_servico/<int:id_profissional>/<int:id_servico>', methods=['GET'])
@validar_token
def get_profissional_servico_by_ids(id_profissional, id_servico, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM PROFISSIONAL_SERVICO WHERE ID_PROFISSIONAL=? AND ID_SERVICO=?", (id_profissional, id_servico))
        profissional_servico = cursor.fetchone()

        if profissional_servico:
            id_profissional, id_servico = profissional_servico
            profissional_servico_data = {
                'id_profissional': id_profissional,
                'id_servico': id_servico
            }
            return jsonify({'profissional_servico': profissional_servico_data})
        else:
            return jsonify({'message': 'Relação não encontrada'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional_servico', methods=['POST'])
@validar_token
def create_profissional_servico(current_user):
    try:
        data = request.get_json()
        id_profissional = data.get('id_profissional')
        id_servico = data.get('id_servico')

        if not id_profissional or not id_servico:
            return jsonify({'message': 'Dados incompletos'}), 400

        cursor = con.cursor()
        cursor.execute("INSERT INTO PROFISSIONAL_SERVICO (ID_PROFISSIONAL, ID_SERVICO) VALUES (?, ?)", (id_profissional, id_servico))
        con.commit()

        return jsonify({'message': 'Relação adicionada com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional_servico/<int:id_profissional>/<int:id_servico>', methods=['PUT'])
@validar_token
def update_profissional_servico(id_profissional, id_servico, current_user):
    try:
        data = request.get_json()

        cursor = con.cursor()
        cursor.execute("UPDATE PROFISSIONAL_SERVICO SET ID_SERVICO=? WHERE ID_PROFISSIONAL=?", (data['id_servico'], id_profissional))
        con.commit()

        return jsonify({'message': 'Relação atualizada com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional_servico/<int:id_profissional>/<int:id_servico>', methods=['DELETE'])
@validar_token
def delete_profissional_servico(id_profissional, id_servico, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("DELETE FROM PROFISSIONAL_SERVICO WHERE ID_PROFISSIONAL=? AND ID_SERVICO=?", (id_profissional, id_servico))
        con.commit()

        return jsonify({'message': 'Relação excluída com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/horario_profissional/<int:id_profissional>', methods=['GET'])
@validar_token
def get_horario_profissional(id_profissional, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM HORARIO_PROFISSIONAL WHERE ID_PROFISSIONAL=?", (id_profissional,))
        horarios = cursor.fetchall()

        output = []
        for horario in horarios:
            id_horario, id_profissional, hora_inicial, hora_final, intervalo_inicial, intervalo_final, segunda, terca, quarta, quinta, sexta, sabado, domingo = horario
            horario_data = {
                'id_horario': id_horario,
                'id_profissional': id_profissional,
                'hora_inicial': hora_inicial.isoformat(),
                'hora_final': hora_final.isoformat(),
                'intervalo_inicial': intervalo_inicial.isoformat(),
                'intervalo_final': intervalo_final.isoformat(),
                'segunda': segunda,
                'terca': terca,
                'quarta': quarta,
                'quinta': quinta,
                'sexta': sexta,
                'sabado': sabado,
                'domingo': domingo
            }
            output.append(horario_data)

        return jsonify({'horarios_profissional': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/horario_profissional', methods=['POST'])
@validar_token
def create_horario_profissional(current_user):
    try:
        data = request.get_json()
        id_profissional = data.get('id_profissional')
        hora_inicial = data.get('hora_inicial')
        hora_final = data.get('hora_final')
        intervalo_inicial = data.get('intervalo_inicial')
        intervalo_final = data.get('intervalo_final')
        segunda = data.get('segunda')
        terca = data.get('terca')
        quarta = data.get('quarta')
        quinta = data.get('quinta')
        sexta = data.get('sexta')
        sabado = data.get('sabado')
        domingo = data.get('domingo')

        if not id_profissional or not hora_inicial or not hora_final or not intervalo_inicial or not intervalo_final:
            return jsonify({'message': 'Dados incompletos'}), 400

        cursor = con.cursor()
        cursor.execute("""
            INSERT INTO HORARIO_PROFISSIONAL (ID_PROFISSIONAL, HORA_INICIAL, HORA_FINAL, INTERVALO_INICIAL, INTERVALO_FINAL, 
            SEGUNDA, TERCA, QUARTA, QUINTA, SEXTA, SABADO, DOMINGO) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (id_profissional, hora_inicial, hora_final, intervalo_inicial, intervalo_final, segunda, terca, quarta, quinta, sexta, sabado, domingo))
        con.commit()

        return jsonify({'message': 'Horário adicionado com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/horario_profissional/<int:id_horario>', methods=['PUT'])
@validar_token
def update_horario_profissional(id_horario, current_user):
    try:
        data = request.get_json()

        cursor = con.cursor()
        cursor.execute("""
            UPDATE HORARIO_PROFISSIONAL 
            SET ID_PROFISSIONAL=?, HORA_INICIAL=?, HORA_FINAL=?, INTERVALO_INICIAL=?, INTERVALO_FINAL=?,
            SEGUNDA=?, TERCA=?, QUARTA=?, QUINTA=?, SEXTA=?, SABADO=?, DOMINGO=?
            WHERE ID_HORARIO_PROFISSIONAL=?
            """, (data['id_profissional'], data['hora_inicial'], data['hora_final'], data['intervalo_inicial'], data['intervalo_final'],
                  data['segunda'], data['terca'], data['quarta'], data['quinta'], data['sexta'], data['sabado'], data['domingo'], id_horario))
        con.commit()

        return jsonify({'message': 'Horário atualizado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/horario_profissional/<int:id_horario>', methods=['DELETE'])
@validar_token
def delete_horario_profissional(id_horario, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("DELETE FROM HORARIO_PROFISSIONAL WHERE ID_HORARIO_PROFISSIONAL=?", (id_horario,))
        con.commit()

        return jsonify({'message': 'Horário excluído com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()


# Rota de logout
@app.route('/logout', methods=['POST'])
@validar_token
def logout(current_user):
    # Aqui você pode simplesmente retornar uma mensagem de sucesso
    # Como o JWT é stateless, não há necessidade de fazer mais nada
    return jsonify({'message': 'Logout realizado com sucesso!'})