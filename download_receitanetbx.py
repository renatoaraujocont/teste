#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diagnóstico Receitanet BX — foco em erro 5002.

Objetivo:
- Executar testes reproduzíveis contra o servidor para descobrir qual combinação
  semântica/protocolo evita o erro 5002.
- Gerar trilha de auditoria (JSONL/CSV) com telemetria por tentativa.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import re
import socket
import ssl
import tempfile
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

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
    transport_mode: str
    length_endian: str
    version: int
    reserved: int
    sni: str
    greeting_hex: str
    status: str
    codigo_detectado: str
    mensagem_detectada: str
    rtt_ms: int
    bytes_recebidos: int
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
        zlib_level: int = 6,
        append_newline: bool = False,
    ) -> bytes:
        raw = text.encode(payload_encoding)
        comp = zlib.compress(raw, level=zlib_level)
        header = bytes([version]) + len(raw).to_bytes(2, byteorder=length_endian, signed=False) + bytes([reserved])
        packet = header + comp
        if append_newline:
            packet += b"\n"
        return packet

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
        key, cert, _ = pkcs12.load_key_and_certificates(data, password.encode("utf-8") if password else None)
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
    """Cliente com modos de transporte para reduzir casos 'sem_resposta'."""

    def __init__(self, host: str, port: int, timeout: int, ssl_ctx: ssl.SSLContext):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ssl_ctx = ssl_ctx

    def round_trip(
        self,
        packet: bytes,
        transport_mode: str,
        sni: str,
        greeting: bytes,
    ) -> Tuple[bytes, int]:
        start = time.monotonic()
        if transport_mode == "plain":
            raw = self._round_trip_plain(packet, greeting)
        elif transport_mode == "tls":
            raw = self._round_trip_tls(packet, sni, greeting)
        elif transport_mode == "tls-no-sni":
            raw = self._round_trip_tls(packet, "", greeting)
        else:
            raise ValueError(f"transport_mode inválido: {transport_mode}")
        rtt_ms = int((time.monotonic() - start) * 1000)
        return raw, rtt_ms

    def _round_trip_plain(self, packet: bytes, greeting: bytes) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            if greeting:
                sock.sendall(greeting)
            sock.sendall(packet)
            return self._recv_all(sock)

    def _round_trip_tls(self, packet: bytes, sni: str, greeting: bytes) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            sni_name = sni if sni else None
            with self.ssl_ctx.wrap_socket(sock, server_hostname=sni_name) as ssock:
                if greeting:
                    ssock.sendall(greeting)
                ssock.sendall(packet)
                return self._recv_all(ssock)

    def _recv_all(self, conn: socket.socket) -> bytes:
        chunks: List[bytes] = []
        while True:
            try:
                chunk = conn.recv(8192)
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


def parse_csv_list(raw: str) -> List[str]:
    return [x.strip() for x in raw.split(",") if x.strip()]


def parse_int_list(raw: str) -> List[int]:
    values: List[int] = []
    for token in parse_csv_list(raw):
        token = token.strip().lower()
        values.append(int(token, 16) if token.startswith("0x") else int(token))
    return values


def parse_greeting(raw: str) -> bytes:
    """
    Aceita:
      - vazio -> b''
      - hex:001122AABB
      - text:HELLO\r\n
    """
    raw = raw.strip()
    if not raw:
        return b""
    if raw.startswith("hex:"):
        return bytes.fromhex(raw[4:])
    if raw.startswith("text:"):
        return raw[5:].encode("latin-1", errors="replace")
    return bytes.fromhex(raw)


def decode_response_best_effort(packet: bytes) -> Tuple[str, str, str]:
    """Retorna status_decode, texto_decodificado, preview."""
    if not packet:
        return "sem_resposta", "", ""

    decode_errors: List[str] = []
    for endian in ("little", "big"):
        for encoding in ("iso-8859-1", "utf-8"):
            try:
                _, text = FrameCodec.decode(packet, payload_encoding=encoding, length_endian=endian)
                return "ok", text, text[:240].replace("\n", " ")
            except Exception as err:
                decode_errors.append(f"{endian}/{encoding}:{type(err).__name__}")

    return "decode_error", "", packet[:120].hex() + " | " + ",".join(decode_errors[:3])


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
    transport_modes: Iterable[str],
    length_endians: Iterable[str],
    versions: Iterable[int],
    reserved_values: Iterable[int],
    sni_values: Iterable[str],
    greeting: bytes,
    append_newline: bool,
) -> List[ProbeResult]:
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    results: List[ProbeResult] = []
    idx = 0

    with out_jsonl.open("w", encoding="utf-8") as jfp:
        product_iter = itertools.product(
            id_sistemas,
            id_papeis,
            campos_inicio,
            transport_modes,
            length_endians,
            versions,
            reserved_values,
            sni_values,
        )

        for id_sistema, id_papel, campo_inicio, transport_mode, length_endian, version, reserved, sni in product_iter:
            idx += 1
            payload = build_properties_payload(
                id_sistema=id_sistema,
                id_papel=id_papel,
                campo_inicio=campo_inicio,
                data_inicio=data_inicio,
                data_fim=data_fim,
            )
            packet = FrameCodec.encode(
                payload,
                version=version,
                reserved=reserved,
                length_endian=length_endian,
                append_newline=append_newline,
            )

            status = "ok"
            detected_code = ""
            detected_msg = ""
            preview = ""
            rtt_ms = 0
            bytes_recv = 0

            try:
                response_packet, rtt_ms = client.round_trip(
                    packet=packet,
                    transport_mode=transport_mode,
                    sni=sni,
                    greeting=greeting,
                )
                bytes_recv = len(response_packet)
                decode_status, response_text, preview = decode_response_best_effort(response_packet)
                status = decode_status
                if decode_status == "ok":
                    detected_code, detected_msg = detect_business_error(response_text)
            except ssl.SSLError as err:
                status = f"ssl_error:{err.__class__.__name__}"
                preview = str(err)[:240]
            except Exception as err:
                status = f"network_error:{err.__class__.__name__}"
                preview = str(err)[:240]

            pr = ProbeResult(
                idx=idx,
                id_sistema=id_sistema,
                id_papel=id_papel,
                campo_inicio=campo_inicio,
                data_inicio=data_inicio,
                data_fim=data_fim,
                transport_mode=transport_mode,
                length_endian=length_endian,
                version=version,
                reserved=reserved,
                sni=sni,
                greeting_hex=greeting.hex(),
                status=status,
                codigo_detectado=detected_code,
                mensagem_detectada=detected_msg,
                rtt_ms=rtt_ms,
                bytes_recebidos=bytes_recv,
                resposta_preview=preview,
            )
            results.append(pr)

            jfp.write(json.dumps(pr.__dict__, ensure_ascii=False) + "\n")
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
                "transportMode",
                "lengthEndian",
                "version",
                "reserved",
                "sni",
                "greetingHex",
                "status",
                "codigoDetectado",
                "mensagemDetectada",
                "rttMs",
                "bytesRecebidos",
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
                    r.transport_mode,
                    r.length_endian,
                    r.version,
                    r.reserved,
                    r.sni,
                    r.greeting_hex,
                    r.status,
                    r.codigo_detectado,
                    r.mensagem_detectada,
                    r.rtt_ms,
                    r.bytes_recebidos,
                    r.resposta_preview,
                ]
            )

    return results


def run_self_test() -> None:
    payload = "id=periodoEntrega\ndataInicio=01/01/2025\ndataFim=31/01/2025"

    for endian in ("little", "big"):
        packet = FrameCodec.encode(payload, length_endian=endian, version=0x02, reserved=0x00)
        header, decoded = FrameCodec.decode(packet, length_endian=endian)
        assert decoded == payload, f"Decode diferente do payload ({endian})"
        assert header["actual_len"] == len(payload.encode("iso-8859-1")), "Tamanho real inválido"

    code, msg = detect_business_error("5002 - Erro no processamento da solicitação")
    assert code == "5002", "Não detectou código 5002"
    assert "5002" in msg, "Mensagem detectada sem código"

    assert parse_greeting("") == b""
    assert parse_greeting("hex:4142") == b"AB"
    assert parse_greeting("text:AB") == b"AB"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Diagnóstico semântico/protocolo do Receitanet BX (erro 5002)")
    p.add_argument("--host", default=HOST_DEFAULT)
    p.add_argument("--port", type=int, default=PORT_DEFAULT)
    p.add_argument("--timeout", type=int, default=20)

    p.add_argument("--pfx", default="", help="Caminho do certificado PFX")
    p.add_argument("--senha", default="", help="Senha do PFX")

    p.add_argument("--id-sistemas", default="100,0", help="Lista CSV de idSistema")
    p.add_argument("--id-papeis", default="1,2", help="Lista CSV de idPapel")
    p.add_argument("--campos-inicio", default="dataInicio,dataIniion", help="Lista CSV de nomes de campo")

    p.add_argument("--transport-modes", default="tls,tls-no-sni,plain", help="CSV: tls,tls-no-sni,plain")
    p.add_argument("--length-endians", default="little,big", help="CSV: little,big")
    p.add_argument("--versions", default="1,2", help="CSV de versões do byte 0 do header")
    p.add_argument("--reserved-values", default="0", help="CSV de valores do byte reservado")
    p.add_argument("--sni-values", default=f"{HOST_DEFAULT},", help="CSV de SNI; vazio permitido")
    p.add_argument("--greeting", default="", help="prefixo opcional: hex:... ou text:...")
    p.add_argument("--append-newline", action="store_true", help="Adiciona \\n ao fim do pacote")

    p.add_argument("--data-inicio", default="01/01/2025")
    p.add_argument("--data-fim", default="31/01/2025")
    p.add_argument("--pause-ms", type=int, default=300)

    p.add_argument("--out-jsonl", default="diagnostico_receitanet/resultados.jsonl")
    p.add_argument("--out-csv", default="diagnostico_receitanet/resultados.csv")
    p.add_argument("--self-test", action="store_true", help="Executa testes locais sem rede")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.self_test:
        run_self_test()
        print("Self-test OK.")
        return 0

    if not args.pfx:
        raise SystemExit("Informe --pfx para testes reais com mTLS.")

    ssl_ctx = MTLSContextFactory.from_pfx(args.pfx, args.senha)
    client = ReceitanetProbeClient(args.host, args.port, args.timeout, ssl_ctx)

    id_sistemas = parse_csv_list(args.id_sistemas)
    id_papeis = parse_csv_list(args.id_papeis)
    campos_inicio = parse_csv_list(args.campos_inicio)
    transport_modes = parse_csv_list(args.transport_modes)
    length_endians = parse_csv_list(args.length_endians)
    versions = parse_int_list(args.versions)
    reserved_values = parse_int_list(args.reserved_values)
    sni_values = [s for s in args.sni_values.split(",")]
    greeting = parse_greeting(args.greeting)

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
        transport_modes=transport_modes,
        length_endians=length_endians,
        versions=versions,
        reserved_values=reserved_values,
        sni_values=sni_values,
        greeting=greeting,
        append_newline=args.append_newline,
    )

    total = len(results)
    sem_resposta = sum(1 for r in results if r.status == "sem_resposta")
    err5002 = sum(1 for r in results if r.codigo_detectado == "5002")
    candidatas = [r for r in results if r.status == "ok" and r.codigo_detectado != "5002"]

    print(f"Tentativas: {total}")
    print(f"Sem resposta: {sem_resposta}")
    print(f"Com código 5002: {err5002}")
    print(f"Candidatas sem 5002: {len(candidatas)}")

    if candidatas:
        print("\nTop 10 candidatas:")
        for r in candidatas[:10]:
            print(
                f"idx={r.idx} idSistema={r.id_sistema} idPapel={r.id_papel} "
                f"modo={r.transport_mode} endian={r.length_endian} v={r.version} "
                f"status={r.status} codigo={r.codigo_detectado or '-'} bytes={r.bytes_recebidos} rtt={r.rtt_ms}ms"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
