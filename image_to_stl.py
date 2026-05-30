#!/usr/bin/env python3
"""
image_to_stl.py - Converte imagens em arquivos STL para impressao 3D.

Suporta dois modos:

  relief      Gera um relevo (heightmap): areas claras ficam ALTAS e areas
              escuras ficam BAIXAS. Bom para placas decorativas, moldes e
              gravacoes em relevo.

  litofania   Gera uma litofania (lithophane): areas escuras ficam GROSSAS e
              areas claras ficam FINAS, de modo que a imagem aparece quando a
              peca e iluminada por tras. Sempre inclui uma base solida.

Uso basico:
  python3 image_to_stl.py foto.jpg saida.stl
  python3 image_to_stl.py foto.jpg saida.stl --mode litofania --largura 100
  python3 image_to_stl.py foto.jpg saida.stl --altura-max 5 --base 1 --inverter

Dependencias: numpy, Pillow
"""

import argparse
import struct
import sys

import numpy as np
from PIL import Image, ImageOps


def carregar_heightmap(caminho, largura_px=None, suavizar=True, inverter=False):
    """Carrega a imagem, converte para tons de cinza e normaliza para [0, 1]."""
    img = Image.open(caminho)
    # Achata canal alfa contra fundo branco para evitar buracos.
    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        fundo = Image.new("RGB", img.size, (255, 255, 255))
        fundo.paste(img.convert("RGBA"), mask=img.convert("RGBA").split()[-1])
        img = fundo
    img = ImageOps.exif_transpose(img)  # respeita orientacao da camera
    img = img.convert("L")  # tons de cinza

    if largura_px and largura_px > 0 and largura_px != img.width:
        nova_altura = max(1, round(img.height * largura_px / img.width))
        img = img.resize((largura_px, nova_altura), Image.LANCZOS)

    dados = np.asarray(img, dtype=np.float64) / 255.0

    if inverter:
        dados = 1.0 - dados

    return dados


def gerar_vertices(heightmap, largura_mm, altura_base_mm, altura_max_mm, modo):
    """
    Constroi a grade de vertices (x, y, z) a partir do heightmap.

    Retorna um array (linhas, colunas, 3) com as coordenadas de cada ponto da
    superficie superior.
    """
    linhas, colunas = heightmap.shape
    escala = largura_mm / colunas  # mm por pixel (mantem proporcao)

    # Coordenadas X/Y no plano. Y invertido para nao espelhar a imagem.
    xs = np.arange(colunas) * escala
    ys = (linhas - 1 - np.arange(linhas)) * escala

    grade_x, grade_y = np.meshgrid(xs, ys)

    if modo == "litofania":
        # Escuro (valor baixo) => mais grosso. Mapeia [0,1] -> [altura_max, base].
        z = altura_base_mm + (1.0 - heightmap) * (altura_max_mm - altura_base_mm)
    else:  # relief
        # Claro (valor alto) => mais alto.
        z = altura_base_mm + heightmap * altura_max_mm

    return np.stack([grade_x, grade_y, z], axis=-1)


def construir_triangulos(topo):
    """
    Gera a lista de triangulos de um solido fechado (watertight):
    superficie superior, base plana e as quatro paredes laterais.
    """
    linhas, colunas, _ = topo.shape
    z_base = topo[..., 2].min() - 1e-6  # base ligeiramente abaixo do ponto mais baixo
    z_base = 0.0  # base no plano z=0

    # Grade inferior: mesmos x/y do topo, z = 0.
    base = topo.copy()
    base[..., 2] = z_base

    triangulos = []

    def quad(a, b, c, d):
        # Dois triangulos para um quadrilatero a-b-c-d (em ordem).
        triangulos.append((a, b, c))
        triangulos.append((a, c, d))

    # --- Superficie superior ---
    for i in range(linhas - 1):
        for j in range(colunas - 1):
            v00 = topo[i, j]
            v01 = topo[i, j + 1]
            v10 = topo[i + 1, j]
            v11 = topo[i + 1, j + 1]
            quad(v00, v10, v11, v01)

    # --- Base (normais para baixo, ordem invertida) ---
    for i in range(linhas - 1):
        for j in range(colunas - 1):
            v00 = base[i, j]
            v01 = base[i, j + 1]
            v10 = base[i + 1, j]
            v11 = base[i + 1, j + 1]
            quad(v00, v01, v11, v10)

    # --- Paredes laterais ---
    # Borda superior (i=0) e inferior (i=linhas-1)
    for j in range(colunas - 1):
        # borda i=0
        quad(topo[0, j], topo[0, j + 1], base[0, j + 1], base[0, j])
        # borda i=linhas-1
        quad(topo[-1, j + 1], topo[-1, j], base[-1, j], base[-1, j + 1])

    # Borda esquerda (j=0) e direita (j=colunas-1)
    for i in range(linhas - 1):
        # borda j=0
        quad(topo[i + 1, 0], topo[i, 0], base[i, 0], base[i + 1, 0])
        # borda j=colunas-1
        quad(topo[i, -1], topo[i + 1, -1], base[i + 1, -1], base[i, -1])

    return np.asarray(triangulos, dtype=np.float32)


def salvar_stl_binario(triangulos, caminho):
    """Escreve a malha como STL binario."""
    n = len(triangulos)
    # Normais por produto vetorial.
    v0 = triangulos[:, 0]
    v1 = triangulos[:, 1]
    v2 = triangulos[:, 2]
    normais = np.cross(v1 - v0, v2 - v0)
    comprimentos = np.linalg.norm(normais, axis=1, keepdims=True)
    comprimentos[comprimentos == 0] = 1.0
    normais = normais / comprimentos

    with open(caminho, "wb") as f:
        f.write(b"image_to_stl gerado por Claude".ljust(80, b"\0"))
        f.write(struct.pack("<I", n))
        for k in range(n):
            f.write(struct.pack("<3f", *normais[k]))
            f.write(struct.pack("<3f", *triangulos[k, 0]))
            f.write(struct.pack("<3f", *triangulos[k, 1]))
            f.write(struct.pack("<3f", *triangulos[k, 2]))
            f.write(struct.pack("<H", 0))  # atributo


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Converte imagens em arquivos STL para impressao 3D.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("entrada", help="Imagem de entrada (PNG, JPG, etc.)")
    p.add_argument("saida", help="Arquivo STL de saida")
    p.add_argument(
        "--mode", "--modo",
        choices=["relief", "litofania"],
        default="relief",
        help="relief (relevo) ou litofania. Padrao: relief",
    )
    p.add_argument(
        "--largura", type=float, default=100.0,
        help="Largura da peca em mm (a altura segue a proporcao). Padrao: 100",
    )
    p.add_argument(
        "--altura-max", type=float, default=3.0,
        help="Altura/relevo maximo em mm. Padrao: 3",
    )
    p.add_argument(
        "--base", type=float, default=1.0,
        help="Espessura da base solida em mm. Padrao: 1",
    )
    p.add_argument(
        "--max-px", type=int, default=400,
        help="Resolucao maxima (pixels na largura). Reduz a contagem de "
             "triangulos. Padrao: 400",
    )
    p.add_argument(
        "--inverter", action="store_true",
        help="Inverte claro/escuro.",
    )
    args = p.parse_args(argv)

    if args.altura_max <= 0:
        p.error("--altura-max deve ser maior que zero.")
    if args.base < 0:
        p.error("--base nao pode ser negativo.")

    try:
        heightmap = carregar_heightmap(
            args.entrada, largura_px=args.max_px, inverter=args.inverter
        )
    except FileNotFoundError:
        print(f"Erro: arquivo nao encontrado: {args.entrada}", file=sys.stderr)
        return 1
    except Exception as e:  # imagem invalida, etc.
        print(f"Erro ao abrir a imagem: {e}", file=sys.stderr)
        return 1

    linhas, colunas = heightmap.shape
    print(f"Imagem: {colunas}x{linhas} px  modo={args.mode}")

    # Litofania sempre precisa de base; relevo usa o valor informado.
    base = args.base if args.mode == "relief" else max(args.base, 0.4)

    topo = gerar_vertices(
        heightmap,
        largura_mm=args.largura,
        altura_base_mm=base,
        altura_max_mm=args.altura_max,
        modo=args.mode,
    )
    triangulos = construir_triangulos(topo)
    salvar_stl_binario(triangulos, args.saida)

    largura_real = args.largura
    altura_real = largura_real * linhas / colunas
    print(
        f"STL salvo: {args.saida}\n"
        f"  Triangulos: {len(triangulos):,}\n"
        f"  Dimensoes:  {largura_real:.1f} x {altura_real:.1f} mm  "
        f"(espessura ate {base + args.altura_max:.1f} mm)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
