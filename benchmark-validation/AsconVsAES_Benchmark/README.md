# Comparativo Ascon-128a (sw) × AES-128-GCM (hw) — ESP32

Sketch que mede, na mesma execução, **Ascon-128a** (criptografia leve em
software, `ascon-suite`) contra **AES-128-GCM** (via mbedTLS, com o bloco AES no
acelerador de hardware do ESP32). É o comparativo central do trabalho
(Cap. 2 / Seção 3.4.3): software leve × silício dedicado.

## O que ele mede
- **Latência** de cifragem (ciclos de clock) em 16/32/64 B, reportando o
  **mínimo** (piso livre de interrupção) de cada algoritmo + a razão AES/Ascon.
- **Heap** por operação (Ascon não aloca; mbedTLS pode alocar — o sketch mostra).
- Um **teste de sanidade** confirma que o AES-GCM cifra/decifra e valida a tag.

## Caveat importante (interpretação)
No **ESP32 clássico**, o AES-GCM do mbedTLS usa o **hardware** para o bloco AES,
mas o **GHASH** (autenticação) é **software** — o GCM totalmente em hardware só
existe no S2/S3/C3. Então o número de AES-GCM aqui é *AES-em-hardware + GHASH-em-
software*, não GCM 100% em hardware. Vale registrar isso na escrita.

Metodologia: como o driver de AES por hardware adquire um mutex (proibido em
seção crítica), **não** se desabilitam interrupções aqui; por isso reporta-se o
**mínimo** de ciclos (livre de interrupção) para ambos, garantindo comparação
justa. O número de Ascon bate com o da Seção 5.2.3 (~6.117 ciclos em 16 B).

## Como rodar
1. Placa ESP32 selecionada, biblioteca `ascon-suite` instalada (mbedTLS já vem
   no core do ESP32).
2. Compilar e gravar `AsconVsAES_Benchmark/AsconVsAES_Benchmark.ino`.
3. Monitor Serial em **115200**.

## Resultado (ESP32 @ 240 MHz)

Log completo em `aes-comparison-results.log`. Resumo:

- **Memória:** ambos sem alocação dinâmica (heap 0).
- **Latência (mín. de ciclos):** o **Ascon-128a (software) é mais rápido** que o
  AES-128-GCM (AES em hardware + GHASH em software) em todos os tamanhos:
  - 16 B: 6.115 vs 8.541 ciclos → **1,40×**
  - 32 B: 7.212 vs 10.650 ciclos → **1,48×**
  - 64 B: 9.406 vs 14.868 ciclos → **1,58×**
- **Por bloco de 16 B:** Ascon ~1.097 ciclos/bloco vs AES-GCM ~2.109 — o custo do
  GHASH em software faz a vantagem do Ascon crescer com o payload.

## Créditos
`ascon128a_aead_*` da biblioteca ascon-suite (Rhys Weatherley / Southern Storm,
MIT) e `mbedtls_gcm_*` do mbedTLS (parte do core do ESP32). O harness de
comparação é de nossa autoria.
