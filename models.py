import fdb

class Cliente:
    def __init__(self, id_cliente, nome, email, telefone, ativo, tentativas_login, senha):
        self.id_cliente = id_cliente
        self.nome = nome
        self.email = email
        self.telefone = telefone
        self.ativo = ativo
        self.tentativas_login = tentativas_login
        self.senha = senha


class Profissional:
    def __init__(self, id_profissional, nome, telefone, ativo):
        self.id_profissional = id_profissional
        self.nome = nome
        self.telefone = telefone
        self.ativo = ativo

class Servico:
    def __init__(self, id_servico, nome, descricao, valor, tempo, ativo):
        self.id_servico = id_servico
        self.nome = nome
        self.descricao = descricao
        self.valor = valor
        self.tempo = tempo
        self.ativo = ativo

class Agenda:
    def __init__(self, id_agenda, id_cliente, id_profissional, id_servico, data_hora, status):
        self.id_agenda = id_agenda
        self.id_cliente = id_cliente
        self.id_profissional = id_profissional
        self.id_servico = id_servico
        self.data_hora = data_hora
        self.status = status

class HorarioProfissional:
    def __init__(self, id_horario_profissional, id_profissional, hora_inicial, hora_final, intervalo_inicial, intervalo_final, segunda, terca, quarta, quinta, sexta, sabado, domingo):
        self.id_horario_profissional = id_horario_profissional
        self.id_profissional = id_profissional
        self.hora_inicial = hora_inicial
        self.hora_final = hora_final
        self.intervalo_inicial = intervalo_inicial
        self.intervalo_final = intervalo_final
        self.segunda = segunda
        self.terca = terca
        self.quarta = quarta
        self.quinta = quinta
        self.sexta = sexta
        self.sabado = sabado
        self.domingo = domingo

class Parametro:
    def __init__(self, id_parametro, nome_empresa, nome_fantasia, descricao, visao, missao, valores, cnpj):
        self.id_parametro = id_parametro
        self.nome_empresa = nome_empresa
        self.nome_fantasia = nome_fantasia
        self.descricao = descricao
        self.visao = visao
        self.missao = missao
        self.valores = valores
        self.cnpj = cnpj

class ProfissionalServico:
    def __init__(self, id_profissional, id_servico):
        self.id_profissional = id_profissional
        self.id_servico = id_servico

