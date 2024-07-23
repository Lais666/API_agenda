from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import fdb
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from models import Usuario, Profissional, Servico, Agenda, HorarioProfissional, Parametro, ProfissionalServico
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

def gerar_token(usuario_id):
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'sub': usuario_id
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

def verificar_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = kwargs.get('current_user')
        if not current_user:
            return jsonify({'erro': 'Usuário não autenticado.'}), 401

        try:
            cursor = con.cursor()
            cursor.execute("SELECT ADMINISTRADOR FROM usuario WHERE ID_usuario=?", (current_user,))
            result = cursor.fetchone()

            if not result or result[0] != 1:
                return jsonify({'erro': 'Acesso negado. Usuário não é administrador.'}), 403

            return f(*args, **kwargs)

        except Exception as e:
            return jsonify({'erro': str(e)}), 500

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



def verificar_disponibilidade(data_hora, id_servico):
    """
    Executa o procedimento armazenado PROFISSIONALDISPONIVEL e retorna os resultados.

    :param data_hora: A data e hora para verificar a disponibilidade.
    :param id_servico: O ID do serviço para verificar a disponibilidade.
    :return: Lista de dicionários com as informações dos profissionais e sua disponibilidade.
    """
    try:
        cursor = con.cursor()

        dt = datetime.strptime(data_hora, '%d-%m-%Y %H:%M:%S')

        # Chamada do procedimento armazenado
        cursor.callproc('PROFISSIONALDISPONIVEL', (dt, id_servico))
        # Buscar resultados
        resultados = cursor.fetchall()

        # Preparar resposta
        resposta = []
        for linha in resultados:
            resposta.append({
                'ID_PROFISSIONAL': linha.ID_PROFISSIONAL,
                'NOME_PROFISSIONAL': linha.NOME_PROFISSIONAL
            })

        return resposta

    except Exception as e:
        print(f'Erro: {str(e)}')
        return []

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Rotas para usuario (exemplo)
@app.route('/usuarios', methods=['GET'])
@validar_token
@verificar_admin
def get_usuarios(current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM usuario")
        usuarios = cursor.fetchall()

        output = []

        for usuario in usuarios:
            id_usuario, nome, email, telefone, ativo, tentativas_login, administrador, senha = usuario

            usuario_data = {
                'id_usuario': id_usuario,
                'nome': nome,
                'email': email,
                'telefone': telefone
                # senha não deve ser retornada para segurança
            }
            output.append(usuario_data)

        return jsonify({'usuarios': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/usuario/<int:id_usuario>', methods=['GET'])
def get_usuario(id_usuario):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM usuario WHERE ID_usuario=?", (id_usuario,))
        usuario = cursor.fetchone()
        if not usuario:
            return jsonify({'message': 'usuario não encontrado'}), 404
        id_usuario, nome, email, telefone, ativo, tentativas_login, administrador, senha = usuario

        usuario_data = {
            'id_usuario': id_usuario,
            'nome': nome,
            'email': email,
            'telefone': telefone
            # senha não deve ser retornada para segurança
        }
        return jsonify(usuario_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/usuario', methods=['POST'])
def create_usuario():
    data = request.get_json()
    # Valida a senha
    if not validar_senha(data['senha']):
        return jsonify({
                           'error': 'Senha inválida. A senha deve ter pelo menos 8 caracteres e incluir uma letra maiúscula, uma letra minúscula, um número e um caractere especial.'}), 400

    hashed_password = bcrypt.generate_password_hash(data['senha']).decode('utf-8')
    tentativas_login = data.get('tentativas_login', 0)
    ativo = data.get('ativo', 1)
    adminstrador = data.get('administrador', 0)
    try:
        cursor = con.cursor()
        cursor.execute("INSERT INTO usuario (NOME, EMAIL, TELEFONE, ATIVO , TENTATIVAS_LOGIN, ADMINISTRADOR, SENHA) VALUES (?, ?, ?, ?, ?, ?,?)",
                       (data['nome'], data['email'], data['telefone'], ativo, tentativas_login, adminstrador, hashed_password))

        con.commit()

        return jsonify({'message': 'Novo usuario criado com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/usuario/<int:id_usuario>', methods=['PUT'])
def update_usuario(id_usuario):
    data = request.get_json()

    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM usuario WHERE ID_usuario=?", (id_usuario,))
        usuario = cursor.fetchone()


        if not usuario:
            return jsonify({'message': 'usuario não encontrado'}), 404
        cursor.execute("UPDATE usuario SET NOME=?, EMAIL=?, TELEFONE=?, ATIVO=?, ADMINISTRADOR=? WHERE ID_usuario=?",
                       (data['nome'], data['email'], data['telefone'], data['ativo'], data['administrador'], id_usuario))


        con.commit()

        return jsonify({'message': 'usuario atualizado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()



@app.route('/usuario/login', methods=['POST'])
def login_usuario():
    auth_data = request.get_json()
    email = auth_data.get('email')
    senha = auth_data.get('senha')

    if not email or not senha:
        return jsonify({'error': 'Email e senha são obrigatórios.'}), 400


    if not email or not senha:
        return jsonify({'error': 'Email e senha são obrigatórios.'}), 400

    cursor = None
    try:
        cursor = con.cursor()

        cursor.execute("SELECT ID_usuario, SENHA, TENTATIVAS_LOGIN, ATIVO FROM usuario WHERE EMAIL=?", (email,))
        usuario = cursor.fetchone()

        if usuario:
            id_usuario, senha_hash, tentativas_login, ativo = usuario



            if ativo == 0:
                return jsonify({'error': 'Conta inativa. Entre em contato com o suporte.'}), 403

            if bcrypt.check_password_hash(senha_hash, senha):
                # Resetar tentativas de login em caso de sucesso

                cursor.execute("UPDATE usuario SET TENTATIVAS_LOGIN = 0 WHERE ID_usuario=?", (id_usuario,))
                con.commit()
                token = gerar_token(id_usuario)

                return jsonify({'message': 'Login bem-sucedido!', 'token': token}), 200
            else:
                # Incrementar contagem de tentativas falhas
                tentativas_login += 1
                if tentativas_login >= 3:

                    cursor.execute("UPDATE usuario SET ATIVO = false, TENTATIVAS_LOGIN = ? WHERE ID_usuario=?",
                                   (tentativas_login, id_usuario))
                    con.commit()
                    return jsonify({'error': 'Número máximo de tentativas de login excedido. Sua conta foi desativada.'}), 403
                else:
                    cursor.execute("UPDATE usuario SET TENTATIVAS_LOGIN = ? WHERE ID_usuario=?",
                                   (tentativas_login, id_usuario))

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
@verificar_admin
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
                'telefone': telefone,
                'ativo': ativo
            }
            output.append(profissional_data)

        return jsonify({'profissionais': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()


@app.route('/profissionais_disponiveis', methods=['GET'])
def profissionais_disponiveis():
    data_hora = request.args.get('data_hora')
    id_servico = request.args.get('id_servico', type=int)

    if not data_hora or id_servico is None:
        return jsonify({'erro': 'Parâmetros ausentes'}), 400

    try:

        dt = datetime.strptime(data_hora, '%d-%m-%Y %H:%M:%S')
        # Chama a função que executa o procedimento armazenado
        disponibilidade = verificar_disponibilidade(dt, id_servico)
        return jsonify(disponibilidade)

    except Exception as e:
        return jsonify({'erro': str(e)}), 500


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
@verificar_admin
def create_profissional(current_user):
    data = request.get_json()
    ativo = data.get('ativo', 1)
    try:
        cursor = con.cursor()
        cursor.execute("INSERT INTO PROFISSIONAL (NOME, TELEFONE, ATIVO) VALUES (?, ?, ?)",

                       (data['nome'], data['telefone'], ativo))


        con.commit()

        return jsonify({'message': 'Novo profissional criado com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional/<int:id_profissional>', methods=['PUT'])
@validar_token
@verificar_admin
def update_profissional(id_profissional, current_user):
    data = request.get_json()

    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM PROFISSIONAL WHERE ID_PROFISSIONAL=?", (id_profissional,))
        profissional = cursor.fetchone()

        if not profissional:
            return jsonify({'message': 'Profissional não encontrado'}), 404

        cursor.execute("UPDATE PROFISSIONAL SET NOME=?, TELEFONE=?, ATIVO=? WHERE ID_PROFISSIONAL=?",

                       (data['nome'], data['telefone'], data['ativo'], id_profissional))

        con.commit()

        return jsonify({'message': 'Profissional atualizado com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/profissional/<int:id_profissional>', methods=['DELETE'])
@validar_token
@verificar_admin
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
def get_servicos():
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM SERVICO")
        servicos = cursor.fetchall()

        output = []
        for servico in servicos:
            id_servico, nome, descricao, valor, tempo, ativo = servico

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
                'tempo': tempo_str,
                'ativo': ativo
            }
            output.append(servico_data)

        return jsonify({'servicos': output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/servico/<int:id_servico>', methods=['GET'])
def get_servico(id_servico):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM SERVICO WHERE ID_SERVICO=?", (id_servico,))
        servico = cursor.fetchone()

        if not servico:
            return jsonify({'message': 'Serviço não encontrado'}), 404

        id_servico, nome, descricao, valor, tempo, ativo = servico
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
@validar_token
@verificar_admin
def create_servico(current_user):
    # Obter dados adicionais do serviço
    data = request.get_json()
    ativo = data.get('ativo', 1)

    file = request.files.get('file')
    if file and file.filename:
        if not allowed_file(file.filename):
            return jsonify({'error': 'Tipo de arquivo não permitido'}), 400

    try:
        cursor = con.cursor()

        # Inserir dados do serviço no banco
        cursor.execute("""
              INSERT INTO SERVICO (NOME, DESCRICAO, VALOR, TEMPO, ATIVO) 
              VALUES (?, ?, ?, ?, ?)
          """, (data['nome'], data['descricao'], data['valor'], data['tempo'], ativo))
        con.commit()

        # Obter o ID do serviço inserido
        cursor.execute("SELECT GEN_ID(GEN_SERVICO_ID, 0) FROM RDB$DATABASE")
        id_servico = cursor.fetchone()[0]

        if file:
            # Salvar o arquivo com o ID do serviço
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            filename = f"servico_{id_servico}.{file_extension}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            return jsonify({'message': 'Serviço criado com sucesso!', 'file_path': file_path}), 201
        else:
            return jsonify({'message': 'Serviço criado com sucesso, mas sem arquivo associado!'}), 201


    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()


@app.route('/servico/<int:id_servico>', methods=['PUT'])
@validar_token
@verificar_admin
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
@verificar_admin
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
            id_agenda, id_usuario, id_profissional, id_servico, data_hora, status = agenda
            agenda_data = {
                'id_agenda': id_agenda,
                'id_usuario': id_usuario,
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
@verificar_admin
def get_agenda(id_agenda, current_user):
    try:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM AGENDA WHERE ID_AGENDA=?", (id_agenda,))
        agenda = cursor.fetchone()

        if not agenda:
            return jsonify({'message': 'Agenda não encontrada'}), 404

        id_agenda, id_usuario, id_profissional, id_servico, data_hora, status = agenda
        agenda_data = {
            'id_agenda': id_agenda,
            'id_usuario': id_usuario,
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
    status = data.get('status', 1)
    # Verificar disponibilidade do profissional
    if not profissional_disponivel(data['id_profissional'], data_hora, data['id_servico']):
        return jsonify({'message': 'Profissional não está disponível neste horário'}), 400

    try:
        cursor = con.cursor()
        cursor.execute("""
            INSERT INTO AGENDA (ID_usuario, ID_PROFISSIONAL, ID_SERVICO, DATA_HORA, STATUS) 
            VALUES (?, ?, ?, ?, ?)
        """, (
            data['id_usuario'],
            data['id_profissional'],
            data['id_servico'],
            data_hora,  # Certifique-se de que data_hora seja um objeto datetime
            status
        ))
        con.commit()

        return jsonify({'message': 'Nova agenda criada com sucesso!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()

@app.route('/agenda/<int:id_agenda>', methods=['PUT'])
@validar_token
@verificar_admin
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
            SET ID_usuario=?, ID_PROFISSIONAL=?, ID_SERVICO=?, DATA_HORA=?, STATUS=? 
            WHERE ID_AGENDA=?
        """, (
            data['id_usuario'],
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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
@verificar_admin
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