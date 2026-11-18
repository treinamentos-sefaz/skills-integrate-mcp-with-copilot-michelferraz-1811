# API de Atividades da Mergington High School

Uma aplicação FastAPI super simples que permite aos estudantes visualizar e se inscrever em atividades extracurriculares.

## Funcionalidades

- Visualizar todas as atividades extracurriculares disponíveis
- Professores autenticados podem inscrever e remover estudantes de atividades

## Primeiros Passos

1. Instale as dependências:

   ```
   pip install fastapi uvicorn
   ```

2. Execute a aplicação:

   ```
   python app.py
   ```

3. Abra seu navegador e vá para:
   - Documentação da API: http://localhost:8000/docs
   - Documentação alternativa: http://localhost:8000/redoc

## Endpoints da API

| Método | Endpoint                                                          | Descrição                                                           |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Obter todas as atividades com seus detalhes e contagem atual de participantes |
| POST   | `/auth/login`                                                      | Iniciar uma sessão de professor                                     |
| POST   | `/auth/logout`                                                     | Encerrar a sessão de professor                                      |
| GET    | `/auth/session`                                                    | Verificar a sessão atual                                            |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Inscrever um estudante (somente professores)                         |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Remover um estudante (somente professores)                          |

## Contas de professores

As credenciais são lidas de `teacher_credentials.json`. O arquivo vem sem contas; adicione os usuários e hashes de senha atribuídos aos professores. Senhas são verificadas com PBKDF2-HMAC-SHA256 (600.000 iterações), e não devem ser armazenadas em texto puro nem enviadas ao repositório.

Gere um hash e sal aleatório com Python:

```python
import hashlib
import getpass
import json
import secrets

password = getpass.getpass("Teacher password: ").encode()
salt = secrets.token_bytes(16)
print(json.dumps({
    "salt": salt.hex(),
    "password_hash": hashlib.pbkdf2_hmac("sha256", password, salt, 600_000).hex(),
}, indent=2))
```

Inclua o objeto gerado em `teachers`, por exemplo:

```json
{
  "teachers": {
    "teacher1": {
      "salt": "<generated salt>",
      "password_hash": "<generated password hash>"
    }
  }
}
```

As sessões são mantidas em memória por até oito horas e terminam quando o servidor reinicia. A lista de participantes continua pública; somente as operações de inscrição e remoção exigem login.

## Modelo de Dados

A aplicação usa um modelo de dados simples com identificadores significativos:

1. **Atividades** - Usa o nome da atividade como identificador:

   - Descrição
   - Cronograma
   - Número máximo de participantes permitidos
   - Lista de emails de estudantes que estão inscritos

2. **Estudantes** - Usa email como identificador:
   - Nome
   - Nível da série

Todos os dados são armazenados na memória, o que significa que os dados serão resetados quando o servidor reiniciar.
