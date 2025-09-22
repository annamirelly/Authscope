# **authscope.py**

## **Descrição**
O script `authscope.py` realiza análise e exploração de cabeçalhos HTTP, cookies e tokens JWT em aplicações web. Seu objetivo é identificar e explorar falhas críticas em mecanismos de autenticação e autorização, como:

- Tokens JWT inseguros (alg:none, segredos fracos, permissões elevadas).
- Vulnerabilidades em cookies (session fixation, path traversal, serialização insegura).
- Manipulação ativa de tokens para escalar privilégios.
- Ataques SSRF e Blind SSRF como vetores alternativos de exploração.

---

## **Funcionalidades**

1. **Análise de Cookies Serializados e JWTs**:
   - Detecta cookies serializados ou JWTs em cabeçalhos.
   - Decodifica e valida tokens, apontando algoritmos inseguros (`alg:none`) e segredos fracos.
   - Suporta manipulação ativa de payloads JWT e fuzzing de roles.

2. **Exploração de Sessões e Caminhos**:
   - Identifica **session fixation** e **path traversal** nos cookies.
   - Checa nomes de cookies conhecidos com histórico de falhas.

3. **Forjamento de Tokens**:
   - Gera JWTs modificados para escalar privilégios (`admin`, `root`, etc.).
   - Permite uso de `alg:none` e simula tokens com segredos fracos.

4. **Fuzzing de Autorizações**:
   - Testa variações de payloads e roles em endpoints protegidos por JWT.
   - Detecta falhas de autorização e privilege escalation.

5. **Ataques SSRF e Blind SSRF**:
   - Gera e testa payloads SSRF nos parâmetros da URL.
   - Usa esquemas como `http://`, `file://`, `gopher://`, etc.
   - Envia requisições para um servidor listener (ex: `webhook.site`) para detectar Blind SSRF.

---

## **Pré-requisitos**

- Python 3.x ou superior
- Bibliotecas necessárias:
  - `requests`
  - `pyjwt`

Instale com:

    pip install requests pyjwt
