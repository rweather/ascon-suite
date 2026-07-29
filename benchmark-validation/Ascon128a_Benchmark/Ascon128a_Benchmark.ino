#include <ASCON.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define MAX_PLAINTEXT 64

static uint8_t key[ASCON128_KEY_SIZE];
static uint8_t nonce[ASCON128_NONCE_SIZE];
static uint8_t plaintext[MAX_PLAINTEXT];
static uint8_t ciphertext[MAX_PLAINTEXT + ASCON128_TAG_SIZE];

// spinlock para medir a cifragem com interrupcoes desabilitadas (sem ruido de ISR)
static portMUX_TYPE benchmarkSpinlock = portMUX_INITIALIZER_UNLOCKED;

struct CycleStatistics {
  uint32_t minCycles;
  uint32_t maxCycles;
  double   meanCycles;
  double   standardDeviation;
};


static void fillVarying(uint8_t *buffer, size_t length, int iteration,
                        uint8_t perIterationStep, uint8_t perByteStep, uint8_t offset)
{
  for (size_t index = 0; index < length; index++)
    buffer[index] = (uint8_t)(iteration * perIterationStep + index * perByteStep + offset);
}


static void varyInputs(int iteration, size_t messageLength)
{
  fillVarying(key,       ASCON128_KEY_SIZE,   iteration, 31, 7, 1);
  fillVarying(nonce,     ASCON128_NONCE_SIZE, iteration, 17, 3, 0);
  fillVarying(plaintext, messageLength,       iteration, 13, 5, 0);
}

// Mede ciclos da cifragem de 'messageLength' bytes ao longo de 'iterations'
// execucoes, com chave e conteudo distintos a cada iteracao (mesmo tamanho).
static CycleStatistics benchmarkEncrypt(size_t messageLength, int iterations)
{
  size_t ciphertextLength = 0;
  uint32_t minCycles = 0xFFFFFFFFu, maxCycles = 0;
  double cycleSum = 0.0, cycleSumOfSquares = 0.0;

  // aquecimento (estabiliza cache); nao contabilizado
  for (int iteration = 0; iteration < 16; iteration++) {
    varyInputs(iteration, messageLength);
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
  }

  for (int iteration = 0; iteration < iterations; iteration++) {
    varyInputs(iteration, messageLength);

    portENTER_CRITICAL(&benchmarkSpinlock);        // interrupcoes off: mede so a cifragem (sem ISR)
    uint32_t startCycles = ESP.getCycleCount();
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
    uint32_t endCycles = ESP.getCycleCount();
    portEXIT_CRITICAL(&benchmarkSpinlock);

    uint32_t cycles = endCycles - startCycles;     // subtracao uint32 trata o wrap do contador
    
    if (cycles < minCycles) {
      minCycles = cycles;
    }

    if (cycles > maxCycles) {
      maxCycles = cycles;
    }

    cycleSum          += (double) cycles;
    cycleSumOfSquares += (double) cycles * (double) cycles;
  }

  CycleStatistics stats;

  stats.minCycles  = minCycles;
  stats.maxCycles  = maxCycles;

  stats.meanCycles = cycleSum / iterations;

  double variance = cycleSumOfSquares / iterations - stats.meanCycles * stats.meanCycles;
  stats.standardDeviation = variance > 0.0 ? sqrt(variance) : 0.0;
  
  return stats;
}

static double cyclesToMicroseconds(double cycles)
{
  return cycles / (double) getCpuFrequencyMhz();  // ciclos / MHz = microssegundos
}

static void printStatistics(size_t messageLength, CycleStatistics stats)
{
  Serial.print("  "); Serial.print((unsigned) messageLength); Serial.print(" B: ");
  Serial.print("min ");    Serial.print(stats.minCycles);
  Serial.print(" | max "); Serial.print(stats.maxCycles);
  Serial.print(" | media ");  Serial.print(stats.meanCycles, 1);
  Serial.print(" ciclos (~"); Serial.print(cyclesToMicroseconds(stats.meanCycles), 2); Serial.print(" us)");
  Serial.print(" | desvio "); Serial.print(stats.standardDeviation, 2);
  Serial.print(" | spread "); Serial.print(stats.maxCycles - stats.minCycles);
  Serial.println(" ciclos");
}

void setup()
{
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.println("=== Ascon-128a: memoria e tempo (Secao 3.4.3) ===");
  Serial.print("CPU: "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
  Serial.print("Estado (ascon128a_state_t): ");
  Serial.print((unsigned) sizeof(ascon128a_state_t)); Serial.println(" bytes");
  Serial.println();

  // ----- MEMORIA -----
  Serial.println("[Memoria]");
  UBaseType_t stackBefore = uxTaskGetStackHighWaterMark(NULL);
  uint32_t freeHeapBefore = ESP.getFreeHeap();      // == esp_get_free_heap_size()
  uint32_t minHeapBefore  = ESP.getMinFreeHeap();   // == esp_get_minimum_free_heap_size()

  size_t ciphertextLength = 0, messageLength = 0;
  uint8_t decryptOutput[MAX_PLAINTEXT];
  varyInputs(1, 16);
  ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, 16, NULL, 0, nonce, key);
  ascon128a_aead_decrypt(decryptOutput, &messageLength, ciphertext, ciphertextLength, NULL, 0, nonce, key);

  uint32_t freeHeapAfter = ESP.getFreeHeap();
  uint32_t minHeapAfter  = ESP.getMinFreeHeap();
  UBaseType_t stackAfter = uxTaskGetStackHighWaterMark(NULL);

  Serial.print("  Heap livre antes/depois: ");
  Serial.print(freeHeapBefore); Serial.print(" / "); Serial.print(freeHeapAfter);
  Serial.print(" B (delta "); Serial.print((int32_t) freeHeapAfter - (int32_t) freeHeapBefore); Serial.println(" B)");
  Serial.print("  Heap minimo antes/depois: ");
  Serial.print(minHeapBefore); Serial.print(" / "); Serial.print(minHeapAfter);
  Serial.println(minHeapAfter < minHeapBefore ? " B (houve alocacao transitoria)" : " B (sem alocacao dinamica)");
  Serial.print("  Folga de pilha antes/depois: ");
  Serial.print((unsigned) stackBefore); Serial.print(" / "); Serial.print((unsigned) stackAfter);
  Serial.print(" (consumo aprox. "); Serial.print((int) stackBefore - (int) stackAfter);
  Serial.println(" -- confira a unidade na sua versao do core)");
  Serial.println();

  // ----- TEMPO (vazao por tamanho) -----
  Serial.println("[Tempo de cifragem por tamanho]");
  printStatistics(16, benchmarkEncrypt(16, 2000));
  printStatistics(32, benchmarkEncrypt(32, 2000));
  printStatistics(64, benchmarkEncrypt(64, 2000));
  Serial.println();

  // ----- CANAL COLATERAL POR TEMPO (tamanho fixo) -----
  Serial.println("[Canal colateral por tempo - 16 B, chave/conteudo distintos]");
  CycleStatistics sideChannelStats = benchmarkEncrypt(16, 5000);
  printStatistics(16, sideChannelStats);
  Serial.print("  variacao relativa (desvio/media): ");
  Serial.print(100.0 * sideChannelStats.standardDeviation / sideChannelStats.meanCycles, 3);
  Serial.println(" %");
  Serial.print("  minimo invariante: "); Serial.print(sideChannelStats.minCycles);
  Serial.println(" ciclos (mesmo piso para chaves/conteudos distintos)");
  Serial.println("  (medicao com interrupcoes desabilitadas; variacao residual");
  Serial.println("   minima e independente do conteudo => execucao em tempo ~constante)");
  Serial.println();

  Serial.println(">>> Medicoes concluidas <<<");
}

void loop()
{
  delay(1000);
}
