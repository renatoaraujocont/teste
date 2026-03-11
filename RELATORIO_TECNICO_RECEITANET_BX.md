# Relatório Técnico: Engenharia Reversa da API Receitanet BX e Erro 5002

**Objetivo:** Documentar o funcionamento do protocolo proprietário do Receitanet BX, as tentativas de implementação em Python e a persistência do erro de negócio 5002, para orientar futuras tentativas de integração sem repetir caminhos falhos.

## 1. O Protocolo Proprietário (Camada de Transporte)

O Receitanet BX não utiliza REST/JSON nem SOAP padrão. Ele utiliza um protocolo binário customizado sobre TCP/TLS (Porta 3443).

### Estrutura do Pacote
Todo pacote enviado ou recebido segue este formato de framing:

```text
[HEADER: 4 bytes] + [PAYLOAD: N bytes]
```

1. **Header (4 bytes):**
   - Byte 0: Versão/Tipo (geralmente `0x01` ou `0x02`).
   - Bytes 1-2: Tamanho do payload descompactado (Big Endian ou Little Endian dependendo da implementação; no Python foi usado `int.to_bytes(2, 'little')` para compatibilidade observada).
   - Byte 3: Reservado/Flag (geralmente `0x00`).
2. **Payload (N bytes):**
   - O conteúdo é comprimido usando **ZLIB**.
   - Após descompactar, o conteúdo é texto (`ISO-8859-1` ou `UTF-8`).

### Handshake TLS
- **Host:** `recnetsped.receita.fazenda.gov.br`
- **Porta:** `3443`
- **Segurança:** requer TLS 1.2.
- **Autenticação:** o servidor exige Client Certificate (e-CPF/e-CNPJ) durante o handshake TLS.

---

## 2. Estrutura Lógica da Requisição (Camada de Aplicação)

O payload descompactado segue um formato chave-valor proprietário ou XML simplificado, dependendo da operação.

### Operação: Solicitar Arquivos (Pesquisa)
Para pesquisar arquivos (SPED, EFD, etc.), o payload identificado na engenharia reversa contém:

- **Identificadores:**
  - `idSistema`: identificador do sistema (ex.: `100` para SPED Fiscal, mas varia).
  - `idPapel`: papel do usuário (ex.: `1` para Contribuinte, `2` para Procurador).
  - `perfil`: tipo de acesso.
- **Critérios (CRITERIOPESQUISA):**
  - Campos dinâmicos baseados no tipo de arquivo.
  - Exemplo comum: data início e fim.

---

## 3. Tentativas Realizadas e Falhas (Erro 5002)

O erro **5002** é retornado pelo servidor da Receita (backend) dentro de um pacote válido. Isso confirma que **o protocolo de rede (TCP/TLS/framing) está correto**, mas o conteúdo da requisição foi rejeitado pela regra de negócio.

### Tentativa A: Payload Padrão de Período
**Payload enviado:**

```properties
id=periodoEntrega
dataInicio=01/01/2025
dataFim=31/01/2025
```

**Resultado:** `5002 - Erro no processamento da solicitação.`

**Diagnóstico:** o servidor recebeu, descompactou, leu as chaves, mas rejeitou os valores ou a combinação de chaves.

### Tentativa B: Variação de Nomes de Campo (String Mining)
Foram encontradas strings suspeitas nos JARs descompilados (`dataIniion` em vez de `dataInicio`).

**Payload enviado:**

```properties
id=periodoEntrega
dataIniion=01/01/2025
# tentativa de typo proposital encontrado no binário
dataFim=31/01/2025
```

**Resultado:** `5002` (persistente).

**Diagnóstico:** o nome do campo não parece ser a única causa, ou `dataIniion` é usado apenas em contextos legados específicos.

### Tentativa C: Consulta de Metadados (Sistemas e Papéis)
Tentativa de consultar a lista de sistemas (`VERSAOSISTEMAS`) para obter os IDs corretos.

**Resultado:** sucesso técnico no envio, mas retorno vazio ou erro genérico dependendo do ambiente.

**Diagnóstico:** a falta dos IDs corretos (`idSistema` e `idPapel` atualizados) é a causa mais provável do 5002 na pesquisa. Se enviado `idSistema=0` ou desatualizado, o backend rejeita.

---

## 4. Conclusão Técnica para Próximas IAs

Se você for tentar corrigir a API Python (`download_receitanetbx.py`), **não** perca tempo com:

1. Handshake TLS (está funcionando).
2. Compressão ZLIB (está funcionando).
3. Framing de bytes (está funcionando).

**O problema é semântico (dados do payload):**

- É necessário descobrir os valores exatos de `idSistema` e `idPapel` para o tipo de arquivo solicitado.
- Esses valores mudam e são baixados dinamicamente pelo cliente oficial na inicialização.
- **Ação recomendada:** interceptar uma requisição válida do cliente oficial (Wireshark com decriptação ou endpoint de debug) para copiar os IDs vigentes.

## Código de referência

A implementação Python analisada está no arquivo [`download_receitanetbx.py`](./download_receitanetbx.py).
