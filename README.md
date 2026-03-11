# teste

## Conteúdo

- `RELATORIO_TECNICO_RECEITANET_BX.md`: relatório técnico com a engenharia reversa do protocolo Receitanet BX e análise do erro 5002.
- `download_receitanetbx.py`: utilitário de diagnóstico semântico para testar combinações de `idSistema`/`idPapel`/campos e rastrear o erro 5002.

## Como testar de forma certeira

### 1) Teste local (sem rede)
Valida codec de framing + extração de código de erro.

```bash
python download_receitanetbx.py --self-test
```

### 2) Teste real com mTLS (matriz semântica)
Executa varredura de combinações para encontrar tentativas sem `5002`.

```bash
python download_receitanetbx.py \
  --pfx /caminho/certificado.pfx \
  --senha 'SUA_SENHA' \
  --id-sistemas '100,200,300' \
  --id-papeis '1,2' \
  --campos-inicio 'dataInicio,dataIniion' \
  --data-inicio 01/01/2025 \
  --data-fim 31/01/2025 \
  --out-jsonl diagnostico_receitanet/resultados.jsonl \
  --out-csv diagnostico_receitanet/resultados.csv
```

Saídas:
- `diagnostico_receitanet/resultados.jsonl` (log detalhado por tentativa)
- `diagnostico_receitanet/resultados.csv` (tabela para filtro rápido)
