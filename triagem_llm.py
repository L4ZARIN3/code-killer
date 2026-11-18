#!/usr/bin/env python3
"""
Triagem de achados do analisador PHP (analise.json) usando uma IA local
via API OpenAI-compatible (LM Studio), com openai + pydantic.

Para cada match de cada arquivo, envia o contexto ao modelo e gera um JSON com:
  analise, arquivo, linha_inicio, linha_fim, fluxo_requisicoes,
  veredito ("confirmado" | "falso positivo")

Requisitos:  pip install openai pydantic

Uso:
  python3 triagem_llm.py analise.json -o triagem.json
  python3 triagem_llm.py analise.json --base-url http://localhost:1234/v1 --model qwen/qwen3-coder-30b
  python3 triagem_llm.py analise.json --no-schema      # nunca usa response_format
  python3 triagem_llm.py analise.json --debug          # imprime a resposta crua do modelo
"""
import argparse
import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

from openai import OpenAI
from pydantic import BaseModel, Field, ValidationError

SYSTEM_PROMPT = """Você é um auditor de segurança de código PHP experiente fazendo triagem de achados de um analisador estático (taint tracking).
Para cada achado, decida se é uma vulnerabilidade REAL e explorável ("confirmado") ou "falso positivo".

Critérios:
- Em FILE_WRITE, avalie se o atacante controla o CAMINHO/NOME do arquivo ou escreve conteúdo em um arquivo executável (.php, .phtml etc.) ou dentro do web root com extensão interpretada. Isso é crítico (webshell / RCE).
- Se o nome do arquivo é fixo e a extensão não é executável (ex.: .txt, .json, .log), o atacante só controla o CONTEÚDO: isso NÃO é RCE. Considere apenas log injection, crescimento ilimitado do arquivo (DoS) ou exposição de dados sensíveis se o arquivo estiver acessível via HTTP. Se não houver impacto relevante, marque "falso positivo"; se houver impacto real (mesmo baixo), marque "confirmado" e deixe claro na análise que o impacto é baixo.
- Considere autenticação, early exit (ex.: `exit;` no início do arquivo), código morto, validação/sanitização e se o fluxo realmente chega ao sink.
- Para SQL_INJECTION e RCE, verifique se há sanitização/prepared statements/whitelist no fluxo.
- Baseie-se SOMENTE no código e no trace fornecidos. Não invente código que você não viu; se faltar contexto, diga isso na análise.

Responda APENAS com um objeto JSON, sem texto fora dele, com os campos:
veredito ("confirmado" ou "falso positivo"), analise (explicação objetiva em português, 3 a 8 frases, com motivo do veredito e impacto), fluxo_requisicoes (lista de passos da requisição do atacante até o sink, origem -> variáveis -> sink, citando números de linha), linha_inicio (primeira linha do fluxo relevante) e linha_fim (linha do sink ou última linha relevante)."""

# Exemplo do formato, usado no prompt quando o response_format está desligado
FORMATO_EXEMPLO = """{
  "veredito": "confirmado" ou "falso positivo",
  "analise": "texto em português",
  "fluxo_requisicoes": ["passo 1 (linha X)", "passo 2 (linha Y)"],
  "linha_inicio": 10,
  "linha_fim": 23
}"""

print_lock = threading.Lock()


def log(msg):
    with print_lock:
        print(msg, file=sys.stderr, flush=True)


class Triagem(BaseModel):
    veredito: Literal["confirmado", "falso positivo"]
    analise: str = Field(description="Explicação objetiva em português")
    fluxo_requisicoes: list[str] = Field(description="Passos da requisição até o sink")
    linha_inicio: int
    linha_fim: int


# --------------------------------------------------------------- Prompt ----
def render_context(context_code):
    linhas = sorted(context_code.items(), key=lambda kv: int(kv[0]))
    return "\n".join(f"{int(n):>5} | {code}" for n, code in linhas)


def build_prompt(file_entry, match, com_exemplo):
    trace = "\n".join(f"- {t}" for t in match.get("taint_trace", [])) or "(sem trace)"
    scope = match.get("scope_range", {})
    texto = (
        f"Arquivo: {file_entry['file']}\n"
        f"Categoria: {match.get('category')}\n"
        f"Sink: {match.get('sink')}  (linha {match.get('line')})\n"
        f"Expressão do sink: {match.get('ast_expression')}\n"
        f"Marcado como contaminado: {match.get('is_tainted')}\n"
        f"Origem da contaminação: {match.get('taint_source')}\n"
        f"Escopo: {match.get('enclosing_scope')} (linhas {scope.get('start')}-{scope.get('end')})\n\n"
        f"Taint trace do analisador:\n{trace}\n\n"
        f"Código (com números de linha):\n```php\n{render_context(match.get('context_code', {}))}\n```\n\n"
        "Faça a triagem deste achado e responda no JSON especificado."
    )
    if com_exemplo:
        texto += f"\n\nFormato exato da resposta (apenas o JSON, nada além dele):\n{FORMATO_EXEMPLO}"
    return texto


# ---------------------------------------------------------------- Parse ----
def parse_triagem(text: str) -> Triagem:
    """Valida a resposta; tolera cercas ``` e blocos <think> de modelos de raciocínio."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I).strip()
    try:
        return Triagem.model_validate_json(text)
    except ValidationError:
        ini, fim = text.find("{"), text.rfind("}")
        if ini == -1 or fim <= ini:
            raise
        return Triagem.model_validate_json(text[ini : fim + 1])


def trace_line_bounds(match):
    nums = [int(n) for t in match.get("taint_trace", []) for n in re.findall(r"Linha (\d+)", t)]
    if not nums:
        return match.get("line"), match.get("line")
    return min(nums), max(nums + [match.get("line") or 0])


# -------------------------------------------------------------- Análise ----
def analyze(client, file_entry, match, args, model, tag):
    base = {
        "arquivo": file_entry["file"],
        "categoria": match.get("category"),
        "sink": match.get("sink"),
    }
    fb_ini, fb_fim = trace_line_bounds(match)
    use_schema = not args.no_schema
    last_err = None

    for tentativa in range(1, args.retries + 2):
        try:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_prompt(file_entry, match, com_exemplo=not use_schema)},
            ]
            kwargs = dict(model=model, messages=messages, temperature=args.temperature)
            if use_schema:
                kwargs["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "triagem",
                        "strict": True,
                        "schema": Triagem.model_json_schema(),
                    },
                }
            resp = client.chat.completions.create(**kwargs)
            conteudo = resp.choices[0].message.content or ""
            if args.debug:
                log(f"  {tag} resposta crua:\n{conteudo}\n")
            t = parse_triagem(conteudo)
            return {
                "analise": t.analise.strip(),
                **base,
                "linha_inicio": t.linha_inicio,
                "linha_fim": t.linha_fim,
                "fluxo_requisicoes": t.fluxo_requisicoes or match.get("taint_trace", []),
                "veredito": t.veredito,
            }
        except ValidationError as e:
            last_err = f"resposta fora do schema: {e.errors()[0]['msg']}"
            log(f"  {tag} tentativa {tentativa}: {last_err}")
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            log(f"  {tag} tentativa {tentativa}: {last_err[:400]}")
            # qualquer falha de API com schema ligado: desliga o schema e tenta de novo
            if use_schema:
                use_schema = False
                log(f"  {tag} desligando response_format e tentando de novo")

    return {
        "analise": f"ERRO na triagem automática: {last_err}",
        **base,
        "linha_inicio": fb_ini,
        "linha_fim": fb_fim,
        "fluxo_requisicoes": match.get("taint_trace", []),
        "veredito": "erro",
    }


def main():
    ap = argparse.ArgumentParser(description="Triagem de achados do analisador PHP com IA (LM Studio).")
    ap.add_argument("input", help="JSON gerado pelo analisador (analise.json)")
    ap.add_argument("-o", "--output", default="triagem.json")
    ap.add_argument("--base-url", default="http://localhost:1234/v1")
    ap.add_argument("--model", help="ID do modelo (padrão: o primeiro carregado no LM Studio)")
    ap.add_argument("--api-key", default="lm-studio")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--timeout", type=float, default=600, help="segundos por requisição")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--workers", type=int, default=1, help="requisições paralelas (local costuma ser 1)")
    ap.add_argument("--no-schema", action="store_true", help="não usar response_format/json_schema")
    ap.add_argument("--debug", action="store_true", help="imprime a resposta crua do modelo")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)

    itens = [(fe, m) for fe in data.get("files", []) for m in fe.get("matches", [])]
    if not itens:
        sys.exit("Nenhum match encontrado no JSON.")

    # max_retries=0: o retry fica por conta do loop em analyze() (que também revalida o JSON)
    client = OpenAI(base_url=args.base_url, api_key=args.api_key, timeout=args.timeout, max_retries=0)

    # Checagem prévia: servidor no ar e modelo disponível
    try:
        ids = [m.id for m in client.models.list().data]
    except Exception as e:
        sys.exit(f"Não consegui falar com {args.base_url}: {type(e).__name__}: {e}\n"
                 "Confira se o servidor do LM Studio está ligado (aba Developer).")

    model = args.model
    if not model:
        if not ids:
            sys.exit("Nenhum modelo carregado no LM Studio. Carregue um modelo ou use --model.")
        model = ids[0]
    elif model not in ids:
        log(f"AVISO: '{model}' não está na lista de modelos do servidor: {ids}")
        log("       Se o JIT loading estiver desligado, as chamadas vão falhar.")

    log(f"Modelo: {model} | achados: {len(itens)} | workers: {args.workers}")

    def run(idx_item):
        idx, (fe, m) = idx_item
        tag = f"[{idx}/{len(itens)}]"
        log(f"{tag} {fe['file']}:{m.get('line')} ({m.get('sink')})")
        r = analyze(client, fe, m, args, model, tag)
        log(f"{tag}    -> {r['veredito']}")
        return r

    resultados = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            for r in ex.map(run, enumerate(itens, 1)):
                resultados.append(r)
    except KeyboardInterrupt:
        log("\nInterrompido; salvando o que já foi processado...")

    contagem = {}
    for r in resultados:
        contagem[r["veredito"]] = contagem.get(r["veredito"], 0) + 1

    saida = {
        "metadata": {
            "origem": args.input,
            "scanned_path": data.get("metadata", {}).get("scanned_path"),
            "modelo": model,
            "total_analisados": len(resultados),
            "resumo": contagem,
        },
        "resultados": resultados,
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, indent=2)
    log(f"\nSalvo em {args.output} | {contagem}")


if __name__ == "__main__":
    main()
