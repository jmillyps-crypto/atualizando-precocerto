from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'Aqui_e_a_chave_da_turma_a'

# CONEXÃO COM O BANCO
host = 'localhost'
database = r'C:\Users\marco\Downloads\BANCOs.FDB'
user = 'SYSDBA'
password = 'SYSDBA'

con = fdb.connect(host=host, database=database, user=user, password=password)


@app.route('/')  # ROTA INCIAL - LANDING PAGE
def index():
    return render_template('index.html')


# ROTA QUE DIRECIONA PARA A PÁGINA CADASTRO DE USUÁRIO
@app.route('/cadastro_usu')
def cadastro_usu():
    return render_template('cadastro.html')


# VERIFICAR SENHA FORTE
def senha_forte(senha):
    if len(senha) < 8:  # senha menor que 8 digitos
        return False
    if senha.islower():  # letra minuscula
        return False
    if senha.isalpha():  # caracter especial
        return False
    if senha.isdigit():  # digitos
        return False
    else:
        return True


@app.route('/cadastrar', methods=['POST'])  # ROTA QUE REALIZA O CADASTRO
def cadastrar():
    nome = request.form['nome'].strip()
    email = request.form['email']
    senha = request.form['senha']
    mao_obra = request.form['mao-de-obra']

    if not nome:
        flash("O campo nome não pode estar vazio")
        return redirect(url_for('cadastro_usu'))

    if not mao_obra:  # SE A MÃO DE OBRA NÃO TIVER SIDO INFORMADA
        flash("Mão de obra não informada!")
        return redirect(url_for('cadastro_usu'))

    mao_obra = float(mao_obra)  # CONVERSÃO DE STRING PARA NÚMERO

    # SE A SENHA INSERIDA NÃO ATINGIR TODOS OS REQUISITOS PARA SENHA FORTE
    if not senha_forte(senha):
        flash(
            "Senha fraca! Precisa conter 8 ou mais caracteres, pelo menos uma letra maiúscula, um número e um caracter especial")
        return redirect(url_for('cadastro_usu'))

    cursor = con.cursor()  # ABRINDO O CURSOR

    try:  # TRATAMENTO DE ERRO

        # SELECIONA O USUARIO QUE POSSUI ESTE EMAIL DIGITADO
        cursor.execute("""SELECT 1
                          FROM usuario u
                          WHERE email = ?""", (email,))

        # CONFERFE SE JÁ TEM ESTE EMAIL CADASTRADO E PEGA SOMENTE ELE
        confere_email = cursor.fetchone()

        if confere_email:  # SE JA TIVER ESTE EMAIL CADASTRADO
            flash('Erro: Email já cadastrado')
            return redirect(url_for('cadastro_usu'))

        if mao_obra < 0:  # SE A MÃO DE OBRA NÃO TIVER SIDO INFORMADA
            flash("Mão de obra não pode ser negativa!")
            return redirect(url_for('cadastro_usu'))

        # GERA CRIPITOGRAFIA DE SENHA
        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

        # EXECUÇÃO DO INSERT - CADASTRO DO USUÁRIO
        cursor.execute(""" INSERT INTO usuario (nome, email, senha, mao_obra, tentativas)
                           VALUES (?, ?, ?, ?, ?) returning id_usuario""", (nome, email, senha_hash, mao_obra, 0))

        id_usuario = cursor.fetchone()[0]
        cursor.execute("""
                       INSERT INTO senhas_utilizadas (id_usuario, senha)
                       VALUES (?, ?)
                       """, (id_usuario, senha_hash))



        con.commit()  # SALVA AS INFORMAÇÕES
        flash("Usuário cadastrado com sucesso")
        return redirect(url_for('login_usu'))


    except Exception as e:  # SE ACONTECER ALGUM ERRO
        flash(f"Ocorreu um error -> {e}")
        con.rollback()  # CANCELA AS MODIFICAÇÕES QUE CAUSARIAM ERRO
        return redirect(url_for('cadastro_usu'))

    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


# ROTA QUE REALIZA O LOGIN DE USUÁRIO
@app.route('/login_usu', methods=['GET', 'POST'])
def login_usu():
    if request.method == 'GET':  # SE A PÁGINA DE LOGIN FOI ACESSADA
        return render_template('login.html')

    email = request.form['email']
    senha = request.form['senha']

    cursor = con.cursor()  # ABRINDO O CURSOR
    try:
        # SELECIONA OS DADOS QUE PERTENCEM AO EMAIL INSERIDO
        cursor.execute("""SELECT id_usuario, nome, senha, tentativas
                          FROM usuario u
                          WHERE u.email = ? """, (email,))

        # CONFERFE SE JÁ TEM ESTES DADOS DE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()

        if not usuario:  # SE NÃO TIVER ESTE USUÁRIO CADASTRADO
            flash("Usuário não encontrado")
            return redirect(url_for('login_usu'))

        # ARMAZENAMENTO DOS CAMPOS DE LOGIN NA VARIAVEL
        id_usuario, nome, senha_hash, tentativas = usuario

        # SE A QUANTIDADE TENTATIVAS DE LOGIN FOR MAIOR
        if tentativas >= 3:
            flash("Usuário Inativo")
            return redirect(url_for('login_usu'))

        if usuario:  # SE ESTE USUÁRIO ESTIVER CADASTRADO
            if bcrypt.check_password_hash(senha_hash,
                                          senha):  # VERIFICA SE A SENHA INSERIDA É IGUAL A QUE FOI CADASTRADA

                # ATUALIZA O NUMERO DE TENTATIVAS PARA ZERO, APOS ACERTAR A SENHA DE USUÁRIO
                cursor.execute("""UPDATE usuario
                                  set tentativas = 0
                                  where id_usuario = ?""", (id_usuario,))

                con.commit()  # SALVA AS INFORMAÇÕES

                session['id_usuario'] = id_usuario  # GUARDA O ID DOS USUÁRIOS LOGADOS
                session['usuario_nome'] = nome  # GUARDA O NOME DOS USUÁRIOS LOGADOS

                flash('Conta logada')
                return redirect(url_for('home'))

            else:

                # ATUALIZA O NÚMERO DE TENTATIVAS (de um em um) A CADA VEZ QUE ERRAR A SENHA DE CADASTRO
                cursor.execute("""UPDATE usuario
                                  set tentativas = tentativas + 1
                                  where id_usuario = ?""", (id_usuario,))

                con.commit()  # SALVA AS INFORMAÇÕES

                # SE O NÚMERO DE TENTATIVAS FOI MAIOR OU IGUAL A 3
                if tentativas + 1 >= 3:
                    flash('Você passou de 3 tentativas! Sua conta foi bloqueada.')
                else:  # SE AS TENTATIVAS MÁXIMAS AINDA NÃO FOREM ATINGIDAS
                    flash('Email ou senha inválida')
                return redirect(url_for('login_usu'))
        return render_template('login.html')

    except Exception as e:  # SE ACONTECER ALGUM ERRO
        flash(f"Ocorreu um error -> {e}")
        con.rollback()  # CANCELA AS MODIFICAÇÕES QUE CAUSARIAM ERRO
        return redirect(url_for('login_usu'))
    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


@app.route('/perfil')  # ROTA DA PAGINA DE PERFIL DO USUARIO
def perfil():
    if 'id_usuario' not in session:  # SENÃO TIVER O ID DE USUÁRIO NA SESSÃO - NÃO ESTIVER LOGADO
        return redirect(url_for('login_usu'))

    cursor = con.cursor()  # ABRINDO O CURSOR
    try:
        # SELECONA OS DADOS QUE PERTENCE AO USUÁRIO LOGADO
        cursor.execute("""SELECT id_usuario, nome, email, senha, mao_obra
                          FROM usuario u
                          WHERE id_usuario = ? """, (session['id_usuario'],))

        # CONFERFE SE JÁ TEM ESTES DADOS DE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()

        # SE ESTE USUÁRIO NÃO EXISTIR
        if not usuario:
            flash('Usuário não encontrado')
            return redirect(url_for('home'))

        # ARMAZENAMENTO DOS CAMPOS - DADOS NA VARIAVEL
        id_usuario, nome, email, senha, mao_obra = usuario

        # RETORNA NA PÁGINA DE PERFIL, AS INFORMAÇÕES CADASTRADAS DO USUÁRIO LOGADO
        return render_template('perfil.html', usuario=usuario,
                               nome=nome,
                               email=email,
                               senha=senha,
                               mao_obra=mao_obra,

                               )

    except Exception as e:  # SE ACONTECER ALGUM ERRO
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('home'))

    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


# ROTA QUE DIRECIONA PARA A PÁGINA EDITAR PERFIL
@app.route('/editar_perfil/<int:id>', methods=['GET', 'POST'])
def editar_perfil(id):
    print('1 entrei ')
    cursor = con.cursor()
    try:
        # SELECIONA OS DADOS QUE PERTENCEM AQUELE ID DE USUÁRIO
        cursor.execute("""SELECT id_usuario, nome, email, senha, mao_obra
                          from usuario
                          WHERE ID_usuario = ?""", (id,))

        # CONFERFE SE JÁ TEM ESTE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()
        print('2 ', usuario)

        if not usuario:  # SE ESTE USUÁRIO NÃO EXISTIR
            flash('Usuário não encontrado')
            return redirect(url_for('index'))

        # ARMAZENAMENTO DOS CAMPOS NA VARIAVEL
        id_usuario, nome, email, senha_atual, mao_obra = usuario

        # ENVIO DOS DADOS INSERIDOS
        if request.method == 'POST':
            nome = request.form['nome'].strip()
            email = request.form['email']
            nova_senha = request.form['senha'].strip()
            mao_obra = request.form['mao_obra']
            print('3')

            if not nome:
                flash("O campo nome não pode estar vazio")
                print(4)
                return redirect(url_for('editar_perfil', id=id_usuario))


            print('4,5', id_usuario)
            # SELECIONA AS SENHAS ANTIGAS DO USUÁRIO (da mais recente pra mais antiga)
            cursor.execute("""SELECT first 3 senha
                              FROM senhas_utilizadas
                              WHERE id_usuario = ?
                                order by id_senhas_utilizadas desc
                           """, (id_usuario,))

            # CONFERE E PEGA TODAS AS SENHAS QUE PERTENCEM AO USUÁRIO
            senhas_antigas = cursor.fetchall()
            print(senhas_antigas)
            print('5')
            # VERIFICAÇÃO DAS 3 ÚLTIMAS SENHAS
            #contador = 0  # CONTROLE DE QUANTAS SENHAS FORAM VERIFICADAS

            # SELECIONA O USUARIO QUE POSSUI ESTE NOVO EMAIL DIGITADO
            cursor.execute("""SELECT id_usuario
                              FROM usuario
                              WHERE email = ? """, (email,))

            # CONFERFE SE JÁ TEM ESTE EMAIL CADASTRADO E PEGA SOMENTE ELE
            email_ja_cadastrado = cursor.fetchone()
            print('10')

            if email_ja_cadastrado:  # SE JA TIVER ESTE EMAIL CADASTRADO EM ALGUM USUÁRIO
                if email_ja_cadastrado[0] != id_usuario:  # SE ESSE EMAIL PERTENCE A UM ID DIFERENTE DESTE USUÁRIO
                    flash('Erro: Email já utilizado por outro usuário')
                    print('11')
                    return redirect(url_for('editar_perfil', id=id_usuario))

            # ANALISA UMA SENHA ANTIGA POR VEZ, ENTRE TODAS AS VERIFICADAS
            for senha_antiga in senhas_antigas:
                print('6')

                # if contador == 3:  # SE VERIFICAR 3 SENHAS
                #     break

                    # VERIFICA SE A NOVA SENHA É IGUAL A UMA DAS QUE FORAM CADASTRADAS
                if bcrypt.check_password_hash(senha_antiga[0], nova_senha):
                    flash('Você não pode usar uma das últimas 3 senhas.')
                    print('7')
                    return redirect(url_for('editar_perfil', id=id_usuario))

                # contador += 1  # VERIFICAÇÕES DE SENHA (uma por vez)


            # # VERIFICAÇÃO DA SENHA ATUAL
            # if bcrypt.check_password_hash(senha_atual, nova_senha):  # SE A NOVA SENHA É IGUAL A SENHA ATUAL
            #     flash('Você não pode usar a senha atual.')
            #     print('8')
            #     return redirect(url_for('editar_perfil', id=id_usuario))

            # GUARDA A SENHA ATUAL NA TABELA
            cursor.execute("""
                           INSERT INTO senhas_utilizadas (id_usuario, senha)
                           VALUES (?, ?)""", (id_usuario, senha_atual))
            print('9')


            if nova_senha == "":
                senha_hash = senha_atual
            else:
                if not senha_forte(nova_senha):
                    flash("Senha fraca")
                    return redirect(url_for('perfil'))
                print('12')

                # GERA CRIPITOGRAFIA DA NOVA SENHA
                senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

            # ALTERAÇÃO/ EDIÇÃO DOS DADOS DO USUÁRIO
            cursor.execute(""" UPDATE usuario
                               SET nome     = ?,
                                   email    = ?,
                                   senha    = ?,
                                   mao_obra = ?
                               where id_usuario = ?""", (nome, email, senha_hash, mao_obra, id))

            session['usuario_nome'] = nome
            print('13')

            con.commit()  # SALVA AS INFORMAÇÕES
            flash("Usuário editado com sucesso")
            return redirect(url_for('perfil'))

        # REDIRECIONAMENTO PARA A PÁGINA 'EDITAR PERFIL'
        return render_template('editar_perfil.html', usuario=usuario)



    except Exception as e:  # SE ACONTECER ALGUM ERRO
        con.rollback()  # CANCELA AS INFORMAÇÕES
        flash(f"Ocorreu um error -> {e}")
        return redirect(url_for('perfil'))


    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


@app.route('/home')  # ROTA INCIAL - LANDING PAGE
def home():
    if 'usuario_nome' not in session:  # SE O NOME DO USUÁRIO NÃO ESTIVER NA SESSÃO - NÃO ESTIVER LOGADO
        return redirect(
            url_for('login_usu'))  # VERIFICA SE O USUARIO ESTÁ LOGADO, SE ESTIVER ABRE A HOME COM AS INFORMAÇÕES

    return render_template(
        'home.html',
        id_usuario=session['id_usuario'],
        usuario_nome=session['usuario_nome']
    )


# ROTA QUE PERMITE SAIR DA CONTA
@app.route('/logout')
def logout():
    if 'id_usuario' in session:  # SE O USUÁRIO ESTIVER NA SESSÃO - LOGADO
        session.pop('id_usuario', None)  # REMOVER O USUARIO/ID DA LISTA
        session.pop('usuario_nome', None)
        flash('Logout com sucesso')

    else:
        flash('Nenhuma conta está logada')

    return redirect(url_for('login_usu'))  # REDIRECIONA PARA PAGINA DE LOGIN




@app.route('/adicionar_insumo')
def adicionar_insumo():
    return render_template("adicionar_insumo.html")



@app.route('/cadastrar_insumo', methods=['POST'])
def cadastrar_insumo():
    print('1')
    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']
    print('2')

    nome = request.form['nome'].strip()
    unidade = request.form['unidade']
    custo_unitario = request.form['custo_unitario']
    estoque = request.form['estoque']
    print('3')

    if not nome:
        flash("O campo nome não pode estar vazio")
        return redirect(url_for('adicionar_insumo'))

    if not estoque:
        flash("Estoque não informado!")
        return redirect(url_for('adicionar_insumo'))

    custo_unitario = float(custo_unitario)
    estoque = float(estoque)
    print('4')

    if custo_unitario < 0:
        flash("Custo unitário não pode ter um valor negativo!")
        return redirect(url_for('adicionar_insumo'))

    if estoque < 0:
        flash("Estoque não pode ter um valor negativo!")
        return redirect(url_for('adicionar_insumo'))
    print('5')

    cursor = con.cursor()

    try:
        print('6')
        cursor.execute("""SELECT 1
                          FROM insumos
                          WHERE nome = ? AND id_usuario = ?""",
                       (nome, id_usuario))
        print('7')

        insumos = cursor.fetchone()
        print(insumos)

        if insumos:
            flash("Erro: Insumo já cadastrado")
            return redirect(url_for('adicionar_insumo'))
        print('8')

        cursor.execute("""INSERT INTO insumos
                          (nome, unidade, custo_unitario, estoque, id_usuario)
                          VALUES (?, ?, ?, ?, ?)""",
                       (nome, unidade, custo_unitario, estoque, id_usuario))

        con.commit()
        print('9')

        flash("Insumo cadastrado com sucesso")
        return redirect(url_for('pagina_insumos'))

    except Exception as e:
        flash(f"Ocorreu um erro -> {e}")
        con.rollback()
        return redirect(url_for('adicionar_insumo'))

    finally:
        cursor.close()



@app.route('/adicionar_produto')
def adicionar_produto():
    return render_template("adicionar_produto.html")


@app.route('/cadastrar_produto',methods=['POST'])
def cadastrar_produto():


    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    nome = request.form['nome'].strip()
    margem_lucro = request.form['lucro']
    preco = request.form['preco']

    margem_lucro = float(margem_lucro)
    preco = float(preco)

    if margem_lucro < 0:
        flash("Margem de lucro não pode ter um valor negativo!")
        return redirect(url_for('adicionar_produto'))

    if preco < 0:
        flash("Preço não pode ter um valor negativo!")
        return redirect(url_for('adicionar_produto'))

    if not nome:
        flash("O campo nome não pode estar vazio")
        return redirect(url_for('adicionar_produto'))

    if not margem_lucro:
        flash("Lucro não informado!")
        return redirect(url_for('adicionar_produto'))

    if not preco:
        flash("Preço não informado!")
        return redirect(url_for('adicionar_produto'))

    cursor = con.cursor()

    try:
        cursor.execute("""SELECT 1
                          FROM produtos
                          WHERE nome = ? AND id_usuario = ?""",
                       (nome, id_usuario))

        produtos = cursor.fetchone()

        if produtos:
            flash("Erro: Produto já cadastrado")
            return redirect(url_for('adicionar_produto'))

        cursor.execute("""INSERT INTO produtos
                          (nome, margem_lucro, preco,id_usuario)
                          VALUES (?, ?, ?, ?)""",
                       (nome, margem_lucro, preco,id_usuario))

        con.commit()

        flash("Produto cadastrado com sucesso")
        return redirect(url_for('pagina_produtos'))

    except Exception as e:
        flash(f"Ocorreu um erro -> {e}")
        con.rollback()
        return redirect(url_for('adicionar_produto'))

    finally:
        cursor.close()


@app.route('/pagina_insumos')
def pagina_insumos():
    return redirect(url_for("lista_insumos"))

@app.route('/lista_insumos')
def lista_insumos():

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    cursor = con.cursor()

    cursor.execute("""SELECT id_insumos, nome, unidade, custo_unitario, estoque
                      FROM insumos
                      WHERE id_usuario = ?
                      ORDER BY id_insumos DESC""", (id_usuario,))

    insumos = cursor.fetchall()

    cursor.close()

    return render_template('lista_insumos.html', insumos=insumos)



@app.route('/editar_insumo/<int:id>', methods=['GET','POST'])
def editar_insumo(id):
    cursor = con.cursor()
    try:
        cursor.execute("""SELECT id_insumos,nome,unidade,custo_unitario,estoque FROM insumos 
                       WHERE id_insumos = ? """, (id,))

        insumos = cursor.fetchone()

        if not insumos:
            flash('Insumo não encontrado!')
            return redirect(url_for("pagina_insumos"))

        if request.method == 'POST':
            nome = request.form['nome'].strip()
            unidade = request.form['unidade']
            custo_unitario = request.form['custo_unitario']
            estoque = request.form['estoque']

            custo_unitario = float(custo_unitario)
            estoque = float(estoque)

            if custo_unitario < 0:
                flash("Custo unitário não pode ter um valor negativo!")
                return redirect(url_for('editar_insumo'))

            if estoque < 0:
                flash("Estoque não pode ter um valor negativo!")
                return redirect(url_for('editar_insumo'))

            cursor.execute(""" UPDATE insumos SET nome = ?, unidade = ?, custo_unitario = ?, estoque = ?
                           where id_insumos = ?""",
                           (nome, unidade, custo_unitario,estoque, id))

            con.commit()
            flash("Insumo editado com sucesso")
            return redirect(url_for('pagina_insumos'))

        return render_template('editar_insumo.html', insumo=insumos)

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for('pagina_insumos'))

    finally:
        cursor.close()


@app.route('/deletar_insumo/<int:id>', methods=['POST'])
def deletar_insumo(id):
    cursor = con.cursor()

    try:
        cursor.execute("""DELETE FROM insumos WHERE id_insumos = ?""", (id,))
        con.commit()

        flash("Insumo deletado com sucesso!")
        return redirect(url_for("pagina_insumos"))

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for("pagina_insumos"))

    finally:
        cursor.close()


@app.route('/pesquisa_insumos', methods=['GET','post'])
def pesquisa_insumos():
    print('1')
    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']
    print('2')
    cursor = con.cursor()
    nome = request.form.get('nome', '').strip()

    print('3')
    try:

        print('4')
        # SELECONA OS DADOS QUE PERTENCE AO USUÁRIO LOGADO
        if nome is None:
            cursor.execute("""SELECT id_insumos, nome, unidade
                            FROM insumos
                            WHERE id_usuario = ? """, (id_usuario,))
        else:
            print('5')
            cursor.execute("""SELECT id_insumos, nome, unidade
                FROM insumos
                where nome like ? 
                and id_usuario = ? """, (f'%{nome}%',id_usuario))

        # CONFERFE SE JÁ TEM ESTES DADOS DE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
            insumos = cursor.fetchone()
            print(insumos)
            # SE ESTE USUÁRIO NÃO EXISTIR
            if not insumos:
                flash('Insumo não encontrado')
                return redirect(url_for('adicionar_insumo'))
            print('6')
        # RETORNA NA PÁGINA DE PERFIL, AS INFORMAÇÕES CADASTRADAS DO USUÁRIO LOGADO
        return render_template('pesquisa_insumo.html', insumos=insumos)

    except Exception as e:  # SE ACONTECER ALGUM ERRO
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('home'))

    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO

#
# @app.route('/pesquisando_insumos/<string:nome>', methods=['GET'])
# def pesquisando_insumos(nome):
#
#     if 'id_usuario' not in session:
#         flash("Você precisa estar logado!")
#         return redirect(url_for('login_usu'))
#
#     id_usuario = session['id_usuario']
#
#     cursor = con.cursor()
#
#     try:
#         # SELECONA OS DADOS QUE PERTENCE AO USUÁRIO LOGADO
#         if nome is None:
#             cursor.execute("""SELECT id_insumos, nome, unidade
#                             FROM insumos
#                             WHERE id_insumo = ? """, (id_usuario,))
#         else:
#             cursor.execute("""SELECT id_insumos, nome, unidade
#                 FROM insumos
#                 where nome = ?
#                 and id_insumo = ? """, ( id_usuario,))
#
#         # CONFERFE SE JÁ TEM ESTES DADOS DE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
#             insumos = cursor.fetchone()
#
#             # SE ESTE USUÁRIO NÃO EXISTIR
#             if not insumos:
#                 flash('Insumo não encontrado')
#                 return redirect(url_for('adicionar_insumo'))
#
#
#
#
#         # RETORNA NA PÁGINA DE PERFIL, AS INFORMAÇÕES CADASTRADAS DO USUÁRIO LOGADO
#         return render_template('pesquisa_insumo.html', insumos=insumos)
#
#     except Exception as e:  # SE ACONTECER ALGUM ERRO
#         flash(f'Ocorreu um erro -> {e}')
#         return redirect(url_for('home'))
#
#     finally:
#         cursor.close()  # FECHA A CONVERSA COM O BANCO


@app.route('/pagina_produtos')
def pagina_produtos():
    return redirect(url_for("lista_produtos"))



@app.route('/lista_produtos')
def lista_produtos():

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    cursor = con.cursor()

    cursor.execute("""SELECT id_produto, nome, margem_lucro, custo_total, sugestao, preco, lucro_unidade
                      FROM produtos
                      WHERE id_usuario = ?
                      ORDER BY id_produto DESC""", (id_usuario,))

    produtos = cursor.fetchall()

    cursor.close()

    return render_template('lista_produtos.html', produtos=produtos)



@app.route('/editar_produto/<int:id>', methods=['GET','POST'])
def editar_produto(id):
    cursor = con.cursor()
    try:
        cursor.execute("""SELECT id_produto, nome, margem_lucro,custo_total,sugestao, preco, lucro_unidade
                              FROM produtos
                              WHERE id_produto = ?""",(id,))

        produtos = cursor.fetchone()

        if not produtos:
            flash('Produto não encontrado!')
            return redirect(url_for("pagina_produtos"))

        if request.method == 'POST':
            nome = request.form['nome'].strip()
            margem_lucro = request.form['lucro']
            preco = request.form['preco']

            margem_lucro = float(margem_lucro)
            preco = float(preco)

            if margem_lucro < 0:
                flash("Margem de lucro não pode ter um valor negativo!")
                return redirect(url_for('adicionar_produto'))

            if preco < 0:
                flash("Preço não pode ter um valor negativo!")
                return redirect(url_for('adicionar_produto'))

            cursor.execute(""" UPDATE produtos SET nome = ?, margem_lucro = ?, preco = ?
                           where id_produto = ?""",
                           (nome, margem_lucro, preco, id))



            con.commit()
            flash("Produto editado com sucesso")
            return redirect(url_for('pagina_produtos'))

        return render_template('editar_produto.html', produto=produtos)

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for('pagina_produtos'))

    finally:
        cursor.close()


@app.route('/deletar_produto/<int:id>', methods=['POST'])
def deletar_produto(id):
    cursor = con.cursor()

    try:
        cursor.execute("""DELETE FROM produtos WHERE id_produto = ?""", (id,))
        con.commit()

        flash("Produto deletado com sucesso!")
        return redirect(url_for("pagina_produtos"))

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for("pagina_produtos"))

    finally:
        cursor.close()





if __name__ == '__main__':
    app.run(debug=True)