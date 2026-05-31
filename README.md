# Imagem → STL (Impressão 3D)

Ferramenta de linha de comando que converte **imagens em arquivos STL** prontos
para fatiar e imprimir em 3D. Gera sólidos fechados (*watertight*), então o
modelo abre sem erros no Cura, PrusaSlicer, Bambu Studio, etc.

## Modos

| Modo        | O que faz                                                                 | Uso típico                         |
|-------------|---------------------------------------------------------------------------|------------------------------------|
| `relief`    | Áreas **claras = altas**, escuras = baixas (mapa de relevo).              | Placas, logos, moldes, gravações.  |
| `litofania` | Áreas **escuras = grossas**, claras = finas. A imagem aparece com luz por trás. | Litofanias (fotos retroiluminadas). |

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

```bash
# Relevo simples (100 mm de largura, até 3 mm de altura)
python3 image_to_stl.py foto.jpg saida.stl

# Litofania de 100 mm
python3 image_to_stl.py foto.jpg lito.stl --mode litofania --largura 100

# Ajustes finos
python3 image_to_stl.py logo.png logo.stl --altura-max 5 --base 1.2 --inverter
```

### Opções

| Opção          | Padrão   | Descrição                                                        |
|----------------|----------|------------------------------------------------------------------|
| `--mode`       | `relief` | `relief` ou `litofania`.                                         |
| `--largura`    | `100`    | Largura da peça em mm (a altura segue a proporção da imagem).    |
| `--altura-max` | `3`      | Relevo/espessura máxima em mm acima da base.                     |
| `--base`       | `1`      | Espessura da base sólida em mm.                                  |
| `--max-px`     | `400`    | Resolução máxima (px na largura). Menor = menos triângulos.      |
| `--inverter`   | —        | Inverte claro/escuro.                                            |

## Dicas

- **Litofanias** ficam melhores com fotos de bom contraste, largura de
  ~100–200 mm, base fina (`--base 0.6`) e `--altura-max` entre 2 e 4 mm.
- Para **relevos/logos**, use imagens com fundo limpo. Use `--inverter` se o
  relevo sair ao contrário do esperado.
- `--max-px` controla o detalhe e o tamanho do arquivo. Aumente para mais
  detalhe, reduza para arquivos mais leves.

## Formatos suportados

Qualquer imagem que o Pillow abra: PNG, JPG, BMP, GIF, TIFF, WEBP… (canal de
transparência é achatado sobre fundo branco).
