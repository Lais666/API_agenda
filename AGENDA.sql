<<<<<<< HEAD
/******************************************************************************/
/****        Generated by IBExpert 2015.12.21.1 23/07/2024 14:17:45        ****/
/******************************************************************************/

SET SQL DIALECT 3;

SET NAMES ISO8859_1;

SET CLIENTLIB 'C:\Program Files (x86)\Firebird\Firebird_4_0\fbclient.dll';

CREATE DATABASE 'LOCALHOST:C:\Users\SN1089702\Downloads\bancofire\AGENDA.fdb'
USER 'SYSDBA' PASSWORD 'sysdba'
PAGE_SIZE 16384
DEFAULT CHARACTER SET ISO8859_1 COLLATION ISO8859_1;



/******************************************************************************/
/****                              Generators                              ****/
/******************************************************************************/

CREATE GENERATOR GEN_SERVICO_ID START WITH 1 INCREMENT BY 1;
SET GENERATOR GEN_SERVICO_ID TO 0;



/******************************************************************************/
/****                          Stored procedures                           ****/
/******************************************************************************/



SET TERM ^ ;

CREATE PROCEDURE CALCULAR_HORA_FINAL (
    TEMPO_SERVICO TIME,
    HORA_INICIAL TIMESTAMP)
RETURNS (
    HORA_FINAL TIME)
AS
BEGIN
  SUSPEND;
END^





CREATE PROCEDURE PROFISSIONALDISPONIVEL (
    DATA_HORA TIMESTAMP,
    ID_SERVICO INTEGER)
RETURNS (
    ID_PROFISSIONAL INTEGER,
    NOME_PROFISSIONAL VARCHAR(255),
    DISPONIVEL SMALLINT)
AS
BEGIN
  SUSPEND;
END^





CREATE PROCEDURE VERIFICARHORARIODISPONIVEL (
    ID_PROFISSIONAL INTEGER,
    DATA_HORA TIMESTAMP,
    ID_SERVICO INTEGER)
RETURNS (
    DISPONIVEL BOOLEAN)
AS
BEGIN
  SUSPEND;
END^






SET TERM ; ^



/******************************************************************************/
/****                           Package headers                            ****/
/******************************************************************************/



SET TERM ^ ;

CREATE PACKAGE RDB$TIME_ZONE_UTIL
AS
^



SET TERM ; ^



/******************************************************************************/
/****                                Tables                                ****/
/******************************************************************************/



CREATE TABLE AGENDA (
    ID_AGENDA        INTEGER GENERATED BY DEFAULT AS IDENTITY,
    ID_USUARIO       INTEGER NOT NULL,
    ID_PROFISSIONAL  INTEGER NOT NULL,
    ID_SERVICO       INTEGER NOT NULL,
    DATA_HORA        TIMESTAMP NOT NULL,
    STATUS           SMALLINT
);


CREATE TABLE HORARIO_PROFISSIONAL (
    ID_HORARIO_PROFISSIONAL  INTEGER GENERATED BY DEFAULT AS IDENTITY,
    ID_PROFISSIONAL          INTEGER NOT NULL,
    HORA_INICIAL             TIME NOT NULL,
    HORA_FINAL               TIME NOT NULL,
    INTERVALO_INICIAL        TIME NOT NULL,
    INTERVALO_FINAL          TIME NOT NULL,
    SEGUNDA                  BOOLEAN NOT NULL,
    TERCA                    BOOLEAN NOT NULL,
    QUARTA                   BOOLEAN NOT NULL,
    QUINTA                   BOOLEAN NOT NULL,
    SEXTA                    BOOLEAN NOT NULL,
    SABADO                   BOOLEAN NOT NULL,
    DOMINGO                  BOOLEAN NOT NULL
);


CREATE TABLE PARAMETRO (
    ID_PARAMETRO   INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME_EMPRESA   VARCHAR(100) NOT NULL,
    NOME_FANTASIA  VARCHAR(100),
    DESCRICAO      VARCHAR(255),
    VISAO          VARCHAR(255),
    MISSAO         VARCHAR(255),
    VALORES        VARCHAR(255),
    CNPJ           VARCHAR(14)
);


CREATE TABLE PROFISSIONAL (
    ID_PROFISSIONAL  INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME             VARCHAR(100) NOT NULL,
    TELEFONE         VARCHAR(20),
    ATIVO            BOOLEAN
);


CREATE TABLE PROFISSIONAL_SERVICO (
    ID_PROFISSIONAL  INTEGER NOT NULL,
    ID_SERVICO       INTEGER NOT NULL
);


CREATE TABLE SERVICO (
    ID_SERVICO  INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME        VARCHAR(100) NOT NULL,
    DESCRICAO   VARCHAR(255),
    VALOR       NUMERIC(15,2),
    TEMPO       TIME,
    ATIVO       BOOLEAN
);


CREATE TABLE USUARIO (
    ID_USUARIO        INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME              VARCHAR(100) NOT NULL,
    EMAIL             VARCHAR(100),
    TELEFONE          VARCHAR(20),
    ATIVO             BOOLEAN,
    TENTATIVAS_LOGIN  INTEGER DEFAULT 0,
    ADMINISTRADOR     BOOLEAN,
    SENHA             VARCHAR(100)
);




/******************************************************************************/
/****                       Autoincrement generators                       ****/
/******************************************************************************/


ALTER TABLE AGENDA ALTER ID_AGENDA RESTART WITH 9;
ALTER TABLE HORARIO_PROFISSIONAL ALTER ID_HORARIO_PROFISSIONAL RESTART WITH 0;
ALTER TABLE PARAMETRO ALTER ID_PARAMETRO RESTART WITH 0;
ALTER TABLE PROFISSIONAL ALTER ID_PROFISSIONAL RESTART WITH 4;
ALTER TABLE SERVICO ALTER ID_SERVICO RESTART WITH 9;
ALTER TABLE USUARIO ALTER ID_USUARIO RESTART WITH 2;




/******************************************************************************/
/****                             Primary keys                             ****/
/******************************************************************************/

ALTER TABLE AGENDA ADD CONSTRAINT PK_AGENDA PRIMARY KEY (ID_AGENDA);
ALTER TABLE HORARIO_PROFISSIONAL ADD CONSTRAINT PK_ID_HORARIO_PROFISSIONAL PRIMARY KEY (ID_HORARIO_PROFISSIONAL);
ALTER TABLE PARAMETRO ADD PRIMARY KEY (ID_PARAMETRO);
ALTER TABLE PROFISSIONAL ADD CONSTRAINT PK_PROFISSIONAL PRIMARY KEY (ID_PROFISSIONAL);
ALTER TABLE PROFISSIONAL_SERVICO ADD CONSTRAINT PK_PROFISSIONAL_SERVICO PRIMARY KEY (ID_PROFISSIONAL, ID_SERVICO);
ALTER TABLE SERVICO ADD CONSTRAINT PK_SERVICO PRIMARY KEY (ID_SERVICO);
ALTER TABLE USUARIO ADD CONSTRAINT PK_USUARIO PRIMARY KEY (ID_USUARIO);


/******************************************************************************/
/****                             Foreign keys                             ****/
/******************************************************************************/

ALTER TABLE AGENDA ADD CONSTRAINT FK_AGENDA_PROFISSIONAL FOREIGN KEY (ID_PROFISSIONAL) REFERENCES PROFISSIONAL (ID_PROFISSIONAL);
ALTER TABLE AGENDA ADD CONSTRAINT FK_AGENDA_SERVICO FOREIGN KEY (ID_SERVICO) REFERENCES SERVICO (ID_SERVICO);
ALTER TABLE AGENDA ADD CONSTRAINT FK_AGENDA_USUARIO FOREIGN KEY (ID_USUARIO) REFERENCES USUARIO (ID_USUARIO);
ALTER TABLE HORARIO_PROFISSIONAL ADD CONSTRAINT FK_HORARIO_PROFISSIONAL FOREIGN KEY (ID_PROFISSIONAL) REFERENCES PROFISSIONAL (ID_PROFISSIONAL);
ALTER TABLE PROFISSIONAL_SERVICO ADD CONSTRAINT FK_PROFISSIONAL_SERVICO_1 FOREIGN KEY (ID_PROFISSIONAL) REFERENCES PROFISSIONAL (ID_PROFISSIONAL);
ALTER TABLE PROFISSIONAL_SERVICO ADD CONSTRAINT FK_PROFISSIONAL_SERVICO_2 FOREIGN KEY (ID_SERVICO) REFERENCES SERVICO (ID_SERVICO);


/******************************************************************************/
/****                               Triggers                               ****/
/******************************************************************************/



SET TERM ^ ;



/******************************************************************************/
/****                         Triggers for tables                          ****/
/******************************************************************************/



/* Trigger: TRIG_SERVICO_ID */
CREATE TRIGGER TRIG_SERVICO_ID FOR SERVICO
ACTIVE BEFORE INSERT POSITION 0
AS
BEGIN
  IF (NEW.ID_servico IS NULL) THEN
    NEW.ID_servico = GEN_ID(GEN_SERVICO_ID, 1);
END
^

SET TERM ; ^



/******************************************************************************/
/****                          Stored procedures                           ****/
/******************************************************************************/



SET TERM ^ ;

ALTER PROCEDURE CALCULAR_HORA_FINAL (
    TEMPO_SERVICO TIME,
    HORA_INICIAL TIMESTAMP)
RETURNS (
    HORA_FINAL TIME)
AS
DECLARE VARIABLE SEGUNDOS_TEMPO1 INTEGER;
DECLARE VARIABLE SEGUNDOS_TEMPO2 INTEGER;
DECLARE VARIABLE TOTAL_SEGUNDOS INTEGER;
DECLARE VARIABLE HORAS INTEGER;
DECLARE VARIABLE MINUTOS INTEGER;
DECLARE VARIABLE SEGUNDOS INTEGER;
BEGIN
    -- Converter TEMPO para segundos
    SEGUNDOS_TEMPO2 = EXTRACT(HOUR FROM TEMPO_SERVICO) * 3600 + EXTRACT(MINUTE FROM TEMPO_SERVICO) * 60 + EXTRACT(SECOND FROM TEMPO_SERVICO);

    -- Converter DATA_HORA para segundos
    SEGUNDOS_TEMPO1 = EXTRACT(HOUR FROM CAST(HORA_INICIAL AS TIME)) * 3600 + EXTRACT(MINUTE FROM CAST(HORA_INICIAL AS TIME)) * 60 + EXTRACT(SECOND FROM CAST(HORA_INICIAL AS TIME));

    -- Somar os segundos
    TOTAL_SEGUNDOS = SEGUNDOS_TEMPO1 + SEGUNDOS_TEMPO2;

    -- Converter o total de segundos de volta para TIME
    HORAS = TOTAL_SEGUNDOS / 3600;
    MINUTOS = (TOTAL_SEGUNDOS - (HORAS * 3600)) / 60;
    SEGUNDOS = TOTAL_SEGUNDOS - (HORAS * 3600) - (MINUTOS * 60);
    -- Converter para TIME
    HORA_FINAL = CAST(HORAS || ':' || MINUTOS || ':' || SEGUNDOS AS TIME);

    SUSPEND;
END^


ALTER PROCEDURE PROFISSIONALDISPONIVEL (
    DATA_HORA TIMESTAMP,
    ID_SERVICO INTEGER)
RETURNS (
    ID_PROFISSIONAL INTEGER,
    NOME_PROFISSIONAL VARCHAR(255),
    DISPONIVEL SMALLINT)
AS
declare variable QTD_HORARIO_PROFISSIONAL integer = 0;
declare variable QTD_HORA_AGENDA integer = 0;
declare variable HORA_FINAL time;
declare variable SEGUNDOS_TEMPO1 integer;
declare variable SEGUNDOS_TEMPO2 integer;
declare variable RESULTADO time;
declare variable TEMPO time;
declare variable TOTAL_SEGUNDOS integer;
declare variable HORAS integer;
declare variable MINUTOS integer;
declare variable SEGUNDOS integer;
declare variable HORA_AGENDADA time;
declare variable TEMPO_AGENDADO time;
begin
disponivel = 0;
    -- Obter o tempo do servi�o
    select SERVICO.TEMPO
    from SERVICO
    where SERVICO.ID_SERVICO = :ID_SERVICO
    and servico.ativo = true
    into :TEMPO;

    select CALCULAR_HORA_FINAL.hora_final from CALCULAR_HORA_FINAL(:TEMPO, cast(:DATA_HORA as time))
    into :HORA_FINAL;

    for
        select
            PROFISSIONAL.ID_PROFISSIONAL,
            PROFISSIONAL.NOME
        from PROFISSIONAL
        inner join profissional_servico on profissional_servico.id_profissional = profissional.id_profissional
        where PROFISSIONAL.ATIVO = true
        into :ID_PROFISSIONAL, :NOME_PROFISSIONAL
    do
    begin
        -- Verificar hor�rio dispon�vel na tabela HORARIO_PROFISSIONAL
        select count(*)
        from HORARIO_PROFISSIONAL
        where HORARIO_PROFISSIONAL.ID_PROFISSIONAL = :ID_PROFISSIONAL
        and (
            cast(:DATA_HORA as date) = current_date
            or (
                (HORARIO_PROFISSIONAL.SEGUNDA = true and extract(weekday from cast(:DATA_HORA as date)) = 1)
                or (HORARIO_PROFISSIONAL.TERCA = true and extract(weekday from cast(:DATA_HORA as date)) = 2)
                or (HORARIO_PROFISSIONAL.QUARTA = true and extract(weekday from cast(:DATA_HORA as date)) = 3)
                or (HORARIO_PROFISSIONAL.QUINTA = true and extract(weekday from cast(:DATA_HORA as date)) = 4)
                or (HORARIO_PROFISSIONAL.SEXTA = true and extract(weekday from cast(:DATA_HORA as date)) = 5)
                or (HORARIO_PROFISSIONAL.SABADO = true and extract(weekday from cast(:DATA_HORA as date)) = 6)
                or (HORARIO_PROFISSIONAL.DOMINGO = true and extract(weekday from cast(:DATA_HORA as date)) = 0)
            )
        )
        and (
            cast(:DATA_HORA as time) between HORARIO_PROFISSIONAL.HORA_INICIAL and HORARIO_PROFISSIONAL.HORA_FINAL
            and not cast(:DATA_HORA as time) between HORARIO_PROFISSIONAL.INTERVALO_INICIAL and HORARIO_PROFISSIONAL.INTERVALO_FINAL
        )
        and (
            cast(:HORA_FINAL as time) between HORARIO_PROFISSIONAL.HORA_INICIAL and HORARIO_PROFISSIONAL.HORA_FINAL
            and not cast(:HORA_FINAL as time) between HORARIO_PROFISSIONAL.INTERVALO_INICIAL and HORARIO_PROFISSIONAL.INTERVALO_FINAL
        )
        into :QTD_HORARIO_PROFISSIONAL;

        -- Verificar agendamentos conflitantes na tabela AGENDA
        QTD_HORA_AGENDA = 0;
        for
            select
                AGENDA.data_hora,
                SERVICO.tempo
            from
                AGENDA
            left join SERVICO on SERVICO.id_servico = AGENDA.id_servico
            where
                agenda.status = 1
                and AGENDA.ID_PROFISSIONAL = :ID_PROFISSIONAL
                and cast(AGENDA.DATA_HORA as date) = cast(:DATA_HORA as date)
            into :HORA_AGENDADA, :TEMPO_AGENDADO
        do
        begin
            select CALCULAR_HORA_FINAL.hora_final from CALCULAR_HORA_FINAL(:TEMPO_AGENDADO, :HORA_AGENDADA)
            into :HORA_FINAL;

            if (cast(:DATA_HORA as time) between :HORA_AGENDADA and :HORA_FINAL) then
                QTD_HORA_AGENDA = 1;
        end

        -- Determinar se o profissional est� dispon�vel
        if ((:QTD_HORARIO_PROFISSIONAL > 0) and (:QTD_HORA_AGENDA = 0)) then
        begin
            DISPONIVEL = 1;
            suspend;
        end
        else
            DISPONIVEL = 0;

    end
end^


ALTER PROCEDURE VERIFICARHORARIODISPONIVEL (
    ID_PROFISSIONAL INTEGER,
    DATA_HORA TIMESTAMP,
    ID_SERVICO INTEGER)
RETURNS (
    DISPONIVEL BOOLEAN)
AS
declare variable QTD_HORARIO_PROFISSIONAL integer = 0;
declare variable QTD_HORA_AGENDA integer = 0;
declare variable HORA_FINAL time;
declare variable SEGUNDOS_TEMPO1 integer;
declare variable SEGUNDOS_TEMPO2 integer;
declare variable RESULTADO time;
declare variable TEMPO time;
declare variable TOTAL_SEGUNDOS integer;
declare variable HORAS integer;
declare variable MINUTOS integer;
declare variable SEGUNDOS integer;
declare variable HORA_AGENDADA time;
declare variable TEMPO_AGENDADO time;
BEGIN

    -- Obter o tempo do servi�o
    SELECT SERVICO.TEMPO
    FROM SERVICO
    WHERE SERVICO.ID_SERVICO = :ID_SERVICO
    and servico.ativo = true
    INTO :TEMPO;

    SELECT CALCULAR_HORA_FINAL.hora_final FROM CALCULAR_HORA_FINAL(:TEMPO, CAST(:DATA_HORA AS TIME))
    INTO :HORA_FINAL ;

     -- Verificar hor�rio dispon�vel na tabela HORARIO_PROFISSIONAL
    SELECT COUNT(*)
    FROM HORARIO_PROFISSIONAL
    WHERE HORARIO_PROFISSIONAL.ID_PROFISSIONAL = :ID_PROFISSIONAL
    AND (
        CAST(:DATA_HORA AS DATE) = CURRENT_DATE
        OR (
            (HORARIO_PROFISSIONAL.SEGUNDA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 1)
            OR (HORARIO_PROFISSIONAL.TERCA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 2)
            OR (HORARIO_PROFISSIONAL.QUARTA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 3)
            OR (HORARIO_PROFISSIONAL.QUINTA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 4)
            OR (HORARIO_PROFISSIONAL.SEXTA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 5)
            OR (HORARIO_PROFISSIONAL.SABADO = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 6)
            OR (HORARIO_PROFISSIONAL.DOMINGO = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 0)
        )
    ) 
    AND (
        CAST(:DATA_HORA AS TIME) BETWEEN HORARIO_PROFISSIONAL.HORA_INICIAL AND HORARIO_PROFISSIONAL.HORA_FINAL
        AND NOT CAST(:DATA_HORA AS TIME) BETWEEN HORARIO_PROFISSIONAL.INTERVALO_INICIAL AND HORARIO_PROFISSIONAL.INTERVALO_FINAL
    )
    AND (
        CAST(:HORA_FINAL AS TIME) BETWEEN HORARIO_PROFISSIONAL.HORA_INICIAL AND HORARIO_PROFISSIONAL.HORA_FINAL
        AND NOT CAST(:HORA_FINAL AS TIME) BETWEEN HORARIO_PROFISSIONAL.INTERVALO_INICIAL AND HORARIO_PROFISSIONAL.INTERVALO_FINAL
    )
    INTO :QTD_HORARIO_PROFISSIONAL;

    -- Verificar agendamentos conflitantes na tabela AGENDA
    FOR
    SELECT AGENDA.data_hora,
    SERVICO.tempo
    FROM AGENDA
    LEFT JOIN SERVICO ON SERVICO.id_servico = AGENDA.id_servico
    WHERE agenda.status = 1
    and AGENDA.ID_PROFISSIONAL = :ID_PROFISSIONAL
    AND CAST(AGENDA.DATA_HORA AS DATE) = CAST(:DATA_HORA AS DATE)
    INTO :hora_agendada,
         :TEMPO_AGENDADO
    DO
    BEGIN
     SELECT CALCULAR_HORA_FINAL.hora_final FROM CALCULAR_HORA_FINAL(:TEMPO_AGENDADO, :hora_agendada )
    INTO :HORA_FINAL ;

    if (CAST(:data_hora AS TIME) between :hora_agendada AND :HORA_FINAL) then
     QTD_HORA_AGENDA  =1;
    END

    -- Determinar se o profissional est� dispon�vel
    IF ((:QTD_HORARIO_PROFISSIONAL > 0) AND (:QTD_HORA_AGENDA = 0)) THEN
        DISPONIVEL = TRUE;
    ELSE
        DISPONIVEL = FALSE;

    SUSPEND;
END^



SET TERM ; ^



/******************************************************************************/
/****                           Package headers                            ****/
/******************************************************************************/



SET TERM ^ ;


SET TERM ; ^



/******************************************************************************/
/****                            Package bodies                            ****/
/******************************************************************************/



SET TERM ^ ;

CREATE PACKAGE BODY RDB$TIME_ZONE_UTIL
AS
^



SET TERM ; ^



/******************************************************************************/
/****                              Privileges                              ****/
/******************************************************************************/


/* Privileges of users */
GRANT SELECT ON MON$ATTACHMENTS TO PUBLIC;
GRANT SELECT ON MON$CALL_STACK TO PUBLIC;
GRANT SELECT ON MON$CONTEXT_VARIABLES TO PUBLIC;
GRANT SELECT ON MON$DATABASE TO PUBLIC;
GRANT SELECT ON MON$IO_STATS TO PUBLIC;
GRANT SELECT ON MON$MEMORY_USAGE TO PUBLIC;
GRANT SELECT ON MON$RECORD_STATS TO PUBLIC;
GRANT SELECT ON MON$STATEMENTS TO PUBLIC;
GRANT SELECT ON MON$TABLE_STATS TO PUBLIC;
GRANT SELECT ON MON$TRANSACTIONS TO PUBLIC;
GRANT SELECT ON SEC$DB_CREATORS TO PUBLIC;
GRANT SELECT ON SEC$GLOBAL_AUTH_MAPPING TO PUBLIC;
GRANT SELECT ON SEC$USERS TO PUBLIC;
GRANT SELECT ON SEC$USER_ATTRIBUTES TO PUBLIC;


/******************************************************************************/
/****                            DDL privileges                            ****/
/******************************************************************************/
=======
/******************************************************************************/
/****        Generated by IBExpert 2015.12.21.1 22/07/2024 11:29:56        ****/
/******************************************************************************/

SET SQL DIALECT 3;

SET NAMES ISO8859_1;

SET CLIENTLIB 'C:\Program Files (x86)\Firebird\Firebird_4_0\fbclient.dll';

CREATE DATABASE 'localhost:C:\Users\Aluno\Downloads\bancofire\agenda.fdb'
USER 'SYSDBA' PASSWORD 'sysdba'
PAGE_SIZE 16384
DEFAULT CHARACTER SET ISO8859_1 COLLATION ISO8859_1;



/******************************************************************************/
/****                          Stored procedures                           ****/
/******************************************************************************/



SET TERM ^ ;

CREATE PROCEDURE CALCULAR_HORA_FINAL (
    TEMPO_SERVICO TIME,
    HORA_INICIAL TIMESTAMP)
RETURNS (
    HORA_FINAL TIME)
AS
BEGIN
  SUSPEND;
END^





CREATE PROCEDURE VERIFICARHORARIODISPONIVEL (
    ID_PROFISSIONAL INTEGER,
    DATA_HORA TIMESTAMP,
    ID_SERVICO INTEGER)
RETURNS (
    DISPONIVEL BOOLEAN)
AS
BEGIN
  SUSPEND;
END^






SET TERM ; ^



/******************************************************************************/
/****                           Package headers                            ****/
/******************************************************************************/



SET TERM ^ ;

CREATE PACKAGE RDB$TIME_ZONE_UTIL
AS
^



SET TERM ; ^



/******************************************************************************/
/****                                Tables                                ****/
/******************************************************************************/



CREATE TABLE AGENDA (
    ID_AGENDA        INTEGER GENERATED BY DEFAULT AS IDENTITY,
    ID_CLIENTE       INTEGER NOT NULL,
    ID_PROFISSIONAL  INTEGER NOT NULL,
    ID_SERVICO       INTEGER NOT NULL,
    DATA_HORA        TIMESTAMP NOT NULL,
    STATUS           SMALLINT
);

CREATE TABLE CLIENTE (
    ID_CLIENTE        INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME              VARCHAR(100) NOT NULL,
    EMAIL             VARCHAR(100),
    TELEFONE          VARCHAR(20),
    ATIVO             BOOLEAN,
    TENTATIVAS_LOGIN  INTEGER DEFAULT 0,
    SENHA             VARCHAR(100)
);

CREATE TABLE HORARIO_PROFISSIONAL (
    ID_HORARIO_PROFISSIONAL  INTEGER GENERATED BY DEFAULT AS IDENTITY,
    ID_PROFISSIONAL          INTEGER NOT NULL,
    HORA_INICIAL             TIME NOT NULL,
    HORA_FINAL               TIME NOT NULL,
    INTERVALO_INICIAL        TIME NOT NULL,
    INTERVALO_FINAL          TIME NOT NULL,
    SEGUNDA                  BOOLEAN NOT NULL,
    TERCA                    BOOLEAN NOT NULL,
    QUARTA                   BOOLEAN NOT NULL,
    QUINTA                   BOOLEAN NOT NULL,
    SEXTA                    BOOLEAN NOT NULL,
    SABADO                   BOOLEAN NOT NULL,
    DOMINGO                  BOOLEAN NOT NULL
);

CREATE TABLE PARAMETRO (
    ID_PARAMETRO   INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME_EMPRESA   VARCHAR(100) NOT NULL,
    NOME_FANTASIA  VARCHAR(100),
    DESCRICAO      VARCHAR(255),
    VISAO          VARCHAR(255),
    MISSAO         VARCHAR(255),
    VALORES        VARCHAR(255),
    CNPJ           VARCHAR(14)
);

CREATE TABLE PROFISSIONAL (
    ID_PROFISSIONAL  INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME             VARCHAR(100) NOT NULL,
    TELEFONE         VARCHAR(20),
    ATIVO            BOOLEAN
);

CREATE TABLE PROFISSIONAL_SERVICO (
    ID_PROFISSIONAL  INTEGER NOT NULL,
    ID_SERVICO       INTEGER NOT NULL
);

CREATE TABLE SERVICO (
    ID_SERVICO  INTEGER GENERATED BY DEFAULT AS IDENTITY,
    NOME        VARCHAR(100) NOT NULL,
    DESCRICAO   VARCHAR(255),
    VALOR       NUMERIC(15,2),
    TEMPO       TIME,
    ATIVO       BOOLEAN
);



/******************************************************************************/
/****                       Autoincrement generators                       ****/
/******************************************************************************/

ALTER TABLE AGENDA ALTER ID_AGENDA RESTART WITH 8;
ALTER TABLE CLIENTE ALTER ID_CLIENTE RESTART WITH 1;
ALTER TABLE HORARIO_PROFISSIONAL ALTER ID_HORARIO_PROFISSIONAL RESTART WITH -1;
ALTER TABLE PARAMETRO ALTER ID_PARAMETRO RESTART WITH -1;
ALTER TABLE PROFISSIONAL ALTER ID_PROFISSIONAL RESTART WITH 1;
ALTER TABLE SERVICO ALTER ID_SERVICO RESTART WITH 0;




/******************************************************************************/
/****                             Primary keys                             ****/
/******************************************************************************/

ALTER TABLE AGENDA ADD CONSTRAINT PK_AGENDA PRIMARY KEY (ID_AGENDA);
ALTER TABLE CLIENTE ADD CONSTRAINT PK_CLIENTE PRIMARY KEY (ID_CLIENTE);
ALTER TABLE HORARIO_PROFISSIONAL ADD CONSTRAINT PK_ID_HORARIO_PROFISSIONAL PRIMARY KEY (ID_HORARIO_PROFISSIONAL);
ALTER TABLE PARAMETRO ADD PRIMARY KEY (ID_PARAMETRO);
ALTER TABLE PROFISSIONAL ADD CONSTRAINT PK_PROFISSIONAL PRIMARY KEY (ID_PROFISSIONAL);
ALTER TABLE PROFISSIONAL_SERVICO ADD CONSTRAINT PK_PROFISSIONAL_SERVICO PRIMARY KEY (ID_PROFISSIONAL, ID_SERVICO);
ALTER TABLE SERVICO ADD CONSTRAINT PK_SERVICO PRIMARY KEY (ID_SERVICO);


/******************************************************************************/
/****                             Foreign keys                             ****/
/******************************************************************************/

ALTER TABLE AGENDA ADD CONSTRAINT FK_AGENDA_CLIENTE FOREIGN KEY (ID_CLIENTE) REFERENCES CLIENTE (ID_CLIENTE);
ALTER TABLE AGENDA ADD CONSTRAINT FK_AGENDA_PROFISSIONAL FOREIGN KEY (ID_PROFISSIONAL) REFERENCES PROFISSIONAL (ID_PROFISSIONAL);
ALTER TABLE AGENDA ADD CONSTRAINT FK_AGENDA_SERVICO FOREIGN KEY (ID_SERVICO) REFERENCES SERVICO (ID_SERVICO);
ALTER TABLE HORARIO_PROFISSIONAL ADD CONSTRAINT FK_HORARIO_PROFISSIONAL FOREIGN KEY (ID_PROFISSIONAL) REFERENCES PROFISSIONAL (ID_PROFISSIONAL);
ALTER TABLE PROFISSIONAL_SERVICO ADD CONSTRAINT FK_PROFISSIONAL_SERVICO_1 FOREIGN KEY (ID_PROFISSIONAL) REFERENCES PROFISSIONAL (ID_PROFISSIONAL);
ALTER TABLE PROFISSIONAL_SERVICO ADD CONSTRAINT FK_PROFISSIONAL_SERVICO_2 FOREIGN KEY (ID_SERVICO) REFERENCES SERVICO (ID_SERVICO);


/******************************************************************************/
/****                          Stored procedures                           ****/
/******************************************************************************/



SET TERM ^ ;

ALTER PROCEDURE CALCULAR_HORA_FINAL (
    TEMPO_SERVICO TIME,
    HORA_INICIAL TIMESTAMP)
RETURNS (
    HORA_FINAL TIME)
AS
DECLARE VARIABLE SEGUNDOS_TEMPO1 INTEGER;
DECLARE VARIABLE SEGUNDOS_TEMPO2 INTEGER;
DECLARE VARIABLE TOTAL_SEGUNDOS INTEGER;
DECLARE VARIABLE HORAS INTEGER;
DECLARE VARIABLE MINUTOS INTEGER;
DECLARE VARIABLE SEGUNDOS INTEGER;
BEGIN
    -- Converter TEMPO para segundos
    SEGUNDOS_TEMPO2 = EXTRACT(HOUR FROM TEMPO_SERVICO) * 3600 + EXTRACT(MINUTE FROM TEMPO_SERVICO) * 60 + EXTRACT(SECOND FROM TEMPO_SERVICO);

    -- Converter DATA_HORA para segundos
    SEGUNDOS_TEMPO1 = EXTRACT(HOUR FROM CAST(HORA_INICIAL AS TIME)) * 3600 + EXTRACT(MINUTE FROM CAST(HORA_INICIAL AS TIME)) * 60 + EXTRACT(SECOND FROM CAST(HORA_INICIAL AS TIME));

    -- Somar os segundos
    TOTAL_SEGUNDOS = SEGUNDOS_TEMPO1 + SEGUNDOS_TEMPO2;

    -- Converter o total de segundos de volta para TIME
    HORAS = TOTAL_SEGUNDOS / 3600;
    MINUTOS = (TOTAL_SEGUNDOS - (HORAS * 3600)) / 60;
    SEGUNDOS = TOTAL_SEGUNDOS - (HORAS * 3600) - (MINUTOS * 60);
    -- Converter para TIME
    HORA_FINAL = CAST(HORAS || ':' || MINUTOS || ':' || SEGUNDOS AS TIME);

    SUSPEND;
END^


ALTER PROCEDURE VERIFICARHORARIODISPONIVEL (
    ID_PROFISSIONAL INTEGER,
    DATA_HORA TIMESTAMP,
    ID_SERVICO INTEGER)
RETURNS (
    DISPONIVEL BOOLEAN)
AS
DECLARE VARIABLE QTD_HORARIO_PROFISSIONAL INTEGER = 0;
DECLARE VARIABLE QTD_HORA_AGENDA INTEGER = 0;
DECLARE VARIABLE HORA_FINAL TIME;
DECLARE VARIABLE SEGUNDOS_TEMPO1 INTEGER;
DECLARE VARIABLE SEGUNDOS_TEMPO2 INTEGER;
DECLARE VARIABLE RESULTADO TIME;
DECLARE VARIABLE TEMPO TIME;
DECLARE VARIABLE TOTAL_SEGUNDOS INTEGER;
declare variable HORAS INTEGER;
declare variable MINUTOS INTEGER;
declare variable SEGUNDOS INTEGER;
declare variable HORA_AGENDADA TIME;
declare variable TEMPO_AGENDADO TIME;
BEGIN

    -- Obter o tempo do servi�o
    SELECT SERVICO.TEMPO
    FROM SERVICO
    WHERE SERVICO.ID_SERVICO = :ID_SERVICO
    INTO :TEMPO;

    SELECT CALCULAR_HORA_FINAL.hora_final FROM CALCULAR_HORA_FINAL(:TEMPO, CAST(:DATA_HORA AS TIME))
    INTO :HORA_FINAL ;

     -- Verificar hor�rio dispon�vel na tabela HORARIO_PROFISSIONAL
    SELECT COUNT(*)
    FROM HORARIO_PROFISSIONAL
    WHERE HORARIO_PROFISSIONAL.ID_PROFISSIONAL = :ID_PROFISSIONAL
    AND (
        CAST(:DATA_HORA AS DATE) = CURRENT_DATE
        OR (
            (HORARIO_PROFISSIONAL.SEGUNDA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 1)
            OR (HORARIO_PROFISSIONAL.TERCA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 2)
            OR (HORARIO_PROFISSIONAL.QUARTA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 3)
            OR (HORARIO_PROFISSIONAL.QUINTA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 4)
            OR (HORARIO_PROFISSIONAL.SEXTA = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 5)
            OR (HORARIO_PROFISSIONAL.SABADO = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 6)
            OR (HORARIO_PROFISSIONAL.DOMINGO = TRUE AND EXTRACT(WEEKDAY FROM CAST(:DATA_HORA AS DATE)) = 0)
        )
    ) 
    AND (
        CAST(:DATA_HORA AS TIME) BETWEEN HORARIO_PROFISSIONAL.HORA_INICIAL AND HORARIO_PROFISSIONAL.HORA_FINAL
        AND NOT CAST(:DATA_HORA AS TIME) BETWEEN HORARIO_PROFISSIONAL.INTERVALO_INICIAL AND HORARIO_PROFISSIONAL.INTERVALO_FINAL
    )
    AND (
        CAST(:HORA_FINAL AS TIME) BETWEEN HORARIO_PROFISSIONAL.HORA_INICIAL AND HORARIO_PROFISSIONAL.HORA_FINAL
        AND NOT CAST(:HORA_FINAL AS TIME) BETWEEN HORARIO_PROFISSIONAL.INTERVALO_INICIAL AND HORARIO_PROFISSIONAL.INTERVALO_FINAL
    )
    INTO :QTD_HORARIO_PROFISSIONAL;

    -- Verificar agendamentos conflitantes na tabela AGENDA
    FOR
    SELECT AGENDA.data_hora,
    SERVICO.tempo
    FROM AGENDA
    LEFT JOIN SERVICO ON SERVICO.id_servico = AGENDA.id_servico
    WHERE AGENDA.ID_PROFISSIONAL = :ID_PROFISSIONAL
    AND CAST(AGENDA.DATA_HORA AS DATE) = CAST(:DATA_HORA AS DATE)
    INTO :hora_agendada,
         :TEMPO_AGENDADO
    DO
    BEGIN
     SELECT CALCULAR_HORA_FINAL.hora_final FROM CALCULAR_HORA_FINAL(:TEMPO_AGENDADO, :hora_agendada )
    INTO :HORA_FINAL ;

    if (CAST(:data_hora AS TIME) between :hora_agendada AND :HORA_FINAL) then
     QTD_HORA_AGENDA  =1;
    END

    -- Determinar se o profissional est� dispon�vel
    IF ((:QTD_HORARIO_PROFISSIONAL > 0) AND (:QTD_HORA_AGENDA = 0)) THEN
        DISPONIVEL = TRUE;
    ELSE
        DISPONIVEL = FALSE;

    SUSPEND;
END^



SET TERM ; ^



/******************************************************************************/
/****                           Package headers                            ****/
/******************************************************************************/



SET TERM ^ ;


SET TERM ; ^



/******************************************************************************/
/****                            Package bodies                            ****/
/******************************************************************************/



SET TERM ^ ;

CREATE PACKAGE BODY RDB$TIME_ZONE_UTIL
AS
^



SET TERM ; ^

>>>>>>> 20e95f420fffdc08d2338a115d69ac2da0b6716b
