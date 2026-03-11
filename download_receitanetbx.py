#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diagnóstico Receitanet BX — foco em erro 5002.

Objetivo:
- Executar testes reproduzíveis contra o servidor para descobrir qual combinação
  semântica de payload (idSistema/idPapel/campos) evita o erro 5002.
- Gerar trilha de auditoria (JSONL/CSV) com request/response por tentativa.

Este script NÃO tenta automatizar todo o fluxo de download. Ele é um utilitário
para investigação precisa de erro de negócio.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import logging
import re
import socket
import ssl
import tempfile
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# Dependência opcional para extrair cert/key de PFX (mTLS).
try:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        pkcs12,
    )
except Exception:  # pragma: no cover
    pkcs12 = None

HOST_DEFAULT = "recnetsped.receita.fazenda.gov.br"
PORT_DEFAULT = 3443


@dataclass
class ProbeResult:
    idx: int
    id_sistema: str
    id_papel: str
    campo_inicio: str
    data_inicio: str
    data_fim: str
    status: str
    codigo_detectado: str
    mensagem_detectada: str
    resposta_preview: str


class FrameCodec:
    """Codec do framing proprietário: [4-byte header] + [zlib payload]."""

    @staticmethod
    def encode(
        text: str,
        version: int = 0x01,
        reserved: int = 0x00,
        payload_encoding: str = "iso-8859-1",
        length_endian: str = "little",
    ) -> bytes:
        raw = text.encode(payload_encoding)
        comp = zlib.compress(raw)
        header = bytes(
            [version]
        ) + len(raw).to_bytes(2, byteorder=length_endian, signed=False) + bytes([reserved])
        return header + comp

    @staticmethod
    def decode(
        packet: bytes,
        payload_encoding: str = "iso-8859-1",
        length_endian: str = "little",
    ) -> Tuple[Dict[str, int], str]:
        if len(packet) < 5:
            raise ValueError("Pacote curto demais para framing.")
        version = packet[0]
        expected_len = int.from_bytes(packet[1:3], byteorder=length_endian, signed=False)
        reserved = packet[3]
        payload = packet[4:]
        raw = zlib.decompress(payload)
        text = raw.decode(payload_encoding, errors="replace")
        return {
            "version": version,
            "expected_len": expected_len,
            "actual_len": len(raw),
            "reserved": reserved,
        }, text


class MTLSContextFactory:
    @staticmethod
    def from_pfx(pfx_path: str, password: str) -> ssl.SSLContext:
        if pkcs12 is None:
            raise RuntimeError("cryptography não disponível. Instale: pip install cryptography")

        data = Path(pfx_path).read_bytes()
        key, cert, _ = pkcs12.load_key_and_certificates(
            data, password.encode("utf-8") if password else None
        )
        if key is None or cert is None:
            raise RuntimeError("PFX inválido ou sem chave/certificado.")

        key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        cert_pem = cert.public_bytes(Encoding.PEM)

        key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
        key_file.write(key_pem)
        cert_file.write(cert_pem)
        key_file.close()
        cert_file.close()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
        return ctx


class ReceitanetProbeClient:
    def __init__(self, host: str, port: int, timeout: int, ssl_ctx: ssl.SSLContext):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ssl_ctx = ssl_ctx

    def round_trip(self, packet: bytes) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            with self.ssl_ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                ssock.sendall(packet)
                chunks: List[bytes] = []
                ssock.settimeout(self.timeout)
                while True:
                    try:
                        chunk = ssock.recv(8192)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
        return b"".join(chunks)


def build_properties_payload(
    id_sistema: str,
    id_papel: str,
    campo_inicio: str,
    data_inicio: str,
    data_fim: str,
    perfil: str = "contribuinte",
) -> str:
    kv = [
        ("idSistema", id_sistema),
        ("idPapel", id_papel),
        ("perfil", perfil),
        ("id", "periodoEntrega"),
        (campo_inicio, data_inicio),
        ("dataFim", data_fim),
    ]
    return "\n".join(f"{k}={v}" for k, v in kv)


def detect_business_error(text: str) -> Tuple[str, str]:
    code_patterns = [r"\b(5002)\b", r"codigo\s*[=:]\s*(\d{4,})", r"<codigo>(\d+)</codigo>"]
    for pat in code_patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            code = m.group(1)
            line = next((ln.strip() for ln in text.splitlines() if code in ln), "")
            return code, line[:240]

    msg = ""
    for pat in [r"erro[^\n]{0,120}", r"mensagem[^\n]{0,160}"]:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            msg = m.group(0)
            break
    return "", msg[:240]


def run_semantic_matrix(
    client: ReceitanetProbeClient,
    out_jsonl: Path,
    out_csv: Path,
    id_sistemas: Iterable[str],
    id_papeis: Iterable[str],
    campos_inicio: Iterable[str],
    data_inicio: str,
    data_fim: str,
    pause_ms: int,
) -> List[ProbeResult]:
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    results: List[ProbeResult] = []
    idx = 0

    with out_jsonl.open("w", encoding="utf-8") as jfp:
        for id_sistema, id_papel, campo_inicio in itertools.product(id_sistemas, id_papeis, campos_inicio):
            idx += 1
            payload = build_properties_payload(
                id_sistema=id_sistema,
                id_papel=id_papel,
                campo_inicio=campo_inicio,
                data_inicio=data_inicio,
                data_fim=data_fim,
            )
            packet = FrameCodec.encode(payload)

            status = "ok"
            detected_code = ""
            detected_msg = ""
            preview = ""

            try:
                response_packet = client.round_trip(packet)
                if not response_packet:
                    status = "sem_resposta"
                else:
                    try:
                        _, response_text = FrameCodec.decode(response_packet)
                        detected_code, detected_msg = detect_business_error(response_text)
                        preview = response_text[:240].replace("\n", " ")
                    except Exception as dec_err:
                        status = f"decode_error:{type(dec_err).__name__}"
                        preview = response_packet[:120].hex()
            except Exception as net_err:
                status = f"network_error:{type(net_err).__name__}"
                preview = str(net_err)[:240]

            pr = ProbeResult(
                idx=idx,
                id_sistema=id_sistema,
                id_papel=id_papel,
                campo_inicio=campo_inicio,
                data_inicio=data_inicio,
                data_fim=data_fim,
                status=status,
                codigo_detectado=detected_code,
                mensagem_detectada=detected_msg,
                resposta_preview=preview,
            )
            results.append(pr)

            jfp.write(
                json.dumps(
                    {
                        "idx": pr.idx,
                        "idSistema": pr.id_sistema,
                        "idPapel": pr.id_papel,
                        "campoInicio": pr.campo_inicio,
                        "dataInicio": pr.data_inicio,
                        "dataFim": pr.data_fim,
                        "status": pr.status,
                        "codigoDetectado": pr.codigo_detectado,
                        "mensagemDetectada": pr.mensagem_detectada,
                        "respostaPreview": pr.resposta_preview,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

            time.sleep(max(0, pause_ms) / 1000)

    with out_csv.open("w", newline="", encoding="utf-8") as cfp:
        writer = csv.writer(cfp)
        writer.writerow(
            [
                "idx",
                "idSistema",
                "idPapel",
                "campoInicio",
                "dataInicio",
                "dataFim",
                "status",
                "codigoDetectado",
                "mensagemDetectada",
                "respostaPreview",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    r.idx,
                    r.id_sistema,
                    r.id_papel,
                    r.campo_inicio,
                    r.data_inicio,
                    r.data_fim,
                    r.status,
                    r.codigo_detectado,
                    r.mensagem_detectada,
                    r.resposta_preview,
                ]
            )

    return results


def run_self_test() -> None:
    payload = "id=periodoEntrega\ndataInicio=01/01/2025\ndataFim=31/01/2025"
    packet = FrameCodec.encode(payload)
    header, decoded = FrameCodec.decode(packet)

    assert decoded == payload, "Decode diferente do payload original"
    assert header["actual_len"] == len(payload.encode("iso-8859-1")), "Tamanho real inválido"

    code, msg = detect_business_error("5002 - Erro no processamento da solicitação")
    assert code == "5002", "Não detectou código 5002"
    assert "5002" in msg, "Mensagem detectada sem código"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Diagnóstico semântico do Receitanet BX (erro 5002)")
    p.add_argument("--host", default=HOST_DEFAULT)
    p.add_argument("--port", type=int, default=PORT_DEFAULT)
    p.add_argument("--timeout", type=int, default=20)

    p.add_argument("--pfx", default="", help="Caminho do certificado PFX")
    p.add_argument("--senha", default="", help="Senha do PFX")

    p.add_argument("--id-sistemas", default="100,0", help="Lista CSV de idSistema")
    p.add_argument("--id-papeis", default="1,2", help="Lista CSV de idPapel")
    p.add_argument("--campos-inicio", default="dataInicio,dataIniion", help="Lista CSV de nomes de campo")

    p.add_argument("--data-inicio", default="01/01/2025")
    p.add_argument("--data-fim", default="31/01/2025")
    p.add_argument("--pause-ms", type=int, default=400)

    p.add_argument("--out-jsonl", default="diagnostico_receitanet/resultados.jsonl")
    p.add_argument("--out-csv", default="diagnostico_receitanet/resultados.csv")
    p.add_argument("--self-test", action="store_true", help="Executa testes locais sem rede")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.self_test:
        run_self_test()
        print("Self-test OK.")
        return 0

    if not args.pfx:
        raise SystemExit("Informe --pfx para testes reais com mTLS.")

    ssl_ctx = MTLSContextFactory.from_pfx(args.pfx, args.senha)
    client = ReceitanetProbeClient(args.host, args.port, args.timeout, ssl_ctx)

    id_sistemas = [x.strip() for x in args.id_sistemas.split(",") if x.strip()]
    id_papeis = [x.strip() for x in args.id_papeis.split(",") if x.strip()]
    campos_inicio = [x.strip() for x in args.campos_inicio.split(",") if x.strip()]

    results = run_semantic_matrix(
        client=client,
        out_jsonl=Path(args.out_jsonl),
        out_csv=Path(args.out_csv),
        id_sistemas=id_sistemas,
        id_papeis=id_papeis,
        campos_inicio=campos_inicio,
        data_inicio=args.data_inicio,
        data_fim=args.data_fim,
        pause_ms=args.pause_ms,
    )

    total = len(results)
    err5002 = sum(1 for r in results if r.codigo_detectado == "5002")
    sucesso_sem_5002 = [r for r in results if r.status == "ok" and r.codigo_detectado != "5002"]

    print(f"Tentativas: {total}")
    print(f"Com código 5002: {err5002}")
    print(f"Candidatas sem 5002: {len(sucesso_sem_5002)}")

    if sucesso_sem_5002:
        print("\nTop 5 candidatas:")
        for r in sucesso_sem_5002[:5]:
            print(
                f"  idx={r.idx} idSistema={r.id_sistema} idPapel={r.id_papel} "
                f"campoInicio={r.campo_inicio} status={r.status} codigo={r.codigo_detectado or '-'}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
