# Benchmark — memória e tempo do Ascon-128a (ESP32)

Sketch Arduino que mede **memória** e **tempo de execução** do Ascon-128a no
ESP32 (Seção 3.4.3), incluindo a verificação de **tempo constante** (canal
colateral por tempo).

## O que ele mede

- **Memória (RAM):** heap livre antes/depois de uma operação, heap mínimo (para
  detectar alocação transitória) e folga de pilha da tarefa
  (`uxTaskGetStackHighWaterMark`). Imprime também o tamanho do estado
  (`ascon128a_state_t`).
- **Tempo (vazão):** ciclos de clock por cifragem em 16, 32 e 64 B
  (`ESP.getCycleCount()`, o mesmo contador CCOUNT citado na metodologia como
  `esp_cpu_get_cycle_count()`), com média, mínimo, máximo e desvio.
- **Canal colateral por tempo:** 5000 cifragens de 16 B com **chave e conteúdo
  distintos a cada vez**, mantendo o tamanho fixo. Se o algoritmo não ramifica
  em função do conteúdo, a variação de ciclos é desprezível (tempo constante).

## O que NÃO está aqui

- **Flash:** medida em tempo de compilação — comparar a saída `Sketch uses X
  bytes of program storage space` **com e sem** as chamadas da cifra.
- **Energia (3.4.4):** medição física (resistor *shunt* + osciloscópio), em
  pasta própria.
- **AES-GCM:** o comparativo software (Ascon) × hardware (AES acelerado) é o
  próximo incremento — há um `TODO` no sketch indicando onde encaixá-lo,
  reusando as funções de medição.

## Como rodar

1. Instalar a biblioteca `ascon-suite` no Arduino IDE.
2. Selecionar a placa ESP32 e a porta serial.
3. Compilar e gravar `Ascon128a_Benchmark/Ascon128a_Benchmark.ino`.
4. Abrir o Monitor Serial em **115200**.

## Resultado (ESP32 @ 240 MHz)

Execução em `benchmark-results.log`. Resumo:

- **Memória:** sem alocação dinâmica (heap delta 0); estado interno de **80 bytes**.
- **Flash:** a biblioteca adiciona **7.048 bytes** (~6,9 KiB) ao firmware —
  294.352 B com a lib vs. 287.304 B sem (chamadas comentadas → o linker descarta
  a lib). A queda de 176 B em "Global variables" são os buffers de teste do
  próprio sketch, não RAM da biblioteca.
- **Tempo de cifragem:** 16 B ≈ 6.117 ciclos (25,49 µs) · 32 B ≈ 7.214 (30,06 µs)
  · 64 B ≈ 9.408 (39,20 µs) — ~+1.100 ciclos por bloco de 128 bits.
- **Tempo constante:** variação relativa de **0,005 %** e mínimo invariante
  (6.117 ciclos) para chaves/conteúdos distintos (interrupções desabilitadas
  durante a medição).

## Créditos

Usa a API do Ascon-128a da biblioteca ascon-suite (Rhys Weatherley / Southern
Storm Software, licença MIT). O harness de medição é de nossa autoria.
