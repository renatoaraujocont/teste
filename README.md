# teste

## Conteúdo

- `RELATORIO_TECNICO_RECEITANET_BX.md`: relatório técnico com a engenharia reversa do protocolo Receitanet BX e análise do erro 5002.
- `download_receitanetbx.py`: utilitário de diagnóstico semântico/protocolo para testar combinações de `idSistema`/`idPapel`/framing/transporte e rastrear o erro 5002.

## Como testar de forma certeira

### 1) Teste local (sem rede)

```bash
python download_receitanetbx.py --self-test
```

### 2) Varredura completa (reduzindo `sem_resposta`)

```bash
python download_receitanetbx.py \
  --pfx /caminho/certificado.pfx \
  --senha 'SUA_SENHA' \
  --id-sistemas '100,200,300' \
  --id-papeis '1,2' \
  --campos-inicio 'dataInicio,dataIniion' \
  --transport-modes 'tls,tls-no-sni,plain' \
  --length-endians 'little,big' \
  --versions '1,2' \
  --reserved-values '0' \
  --sni-values 'recnetsped.receita.fazenda.gov.br,' \
  --data-inicio 01/01/2025 \
  --data-fim 31/01/2025 \
  --out-jsonl diagnostico_receitanet/resultados.jsonl \
  --out-csv diagnostico_receitanet/resultados.csv
```

### 3) Teste com greeting opcional

```bash
python download_receitanetbx.py \
  --pfx /caminho/certificado.pfx \
  --senha 'SUA_SENHA' \
  --greeting 'text:HELLO\r\n'
```

## Saídas

- `diagnostico_receitanet/resultados.jsonl`: log completo por tentativa.
- `diagnostico_receitanet/resultados.csv`: tabela para filtrar padrões (`sem_resposta`, `decode_error`, `5002`, etc.).
