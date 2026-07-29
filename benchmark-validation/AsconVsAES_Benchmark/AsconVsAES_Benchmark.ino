#include <ASCON.h>
#include "mbedtls/gcm.h"
#include <string.h>

#define MAX_PLAINTEXT 64

static uint8_t key[ASCON128_KEY_SIZE];
static uint8_t nonce[ASCON128_NONCE_SIZE];
static uint8_t initializationVector[12];           // IV do GCM (12 B = 96 bits, caso nativo/rapido)
static uint8_t plaintext[MAX_PLAINTEXT];
static uint8_t ciphertext[MAX_PLAINTEXT + ASCON128_TAG_SIZE];
static uint8_t aesCiphertext[MAX_PLAINTEXT];
static uint8_t aesTag[16];

struct CycleStatistics {
  uint32_t minCycles;
  uint32_t maxCycles;
  double   meanCycles;
};

// Preenche um buffer de forma deterministica: varia por iteracao (desloca o
// array inteiro) E por posicao (rampa entre os bytes). Nao e aleatoriedade real
// -- so garante conteudo distinto a cada chamada, suficiente para o teste de
// tempo constante. perIterationStep/perByteStep/offset sao coeficientes
// arbitrarios (apenas != 0 e distintos por buffer).
static void fillVarying(uint8_t *buffer, size_t length, int iteration,
                        uint8_t perIterationStep, uint8_t perByteStep, uint8_t offset)
{
  for (size_t index = 0; index < length; index++)
    buffer[index] = (uint8_t)(iteration * perIterationStep + index * perByteStep + offset);
}

// Varia key/nonce/IV/plaintext a cada iteracao (mesmo tamanho).
static void varyInputs(int iteration, size_t messageLength)
{
  fillVarying(key,                  ASCON128_KEY_SIZE,            iteration, 31, 7, 1);
  fillVarying(nonce,                ASCON128_NONCE_SIZE,          iteration, 17, 3, 0);
  fillVarying(initializationVector, sizeof(initializationVector), iteration, 19, 5, 0);
  fillVarying(plaintext,            messageLength,                iteration, 13, 5, 0);
}

static double cyclesToMicroseconds(double cycles) { return cycles / (double) getCpuFrequencyMhz(); }

// ----- Ascon-128a (software) -----
static CycleStatistics benchmarkAscon(size_t messageLength, int iterations)
{
  size_t ciphertextLength = 0;
  uint32_t minCycles = 0xFFFFFFFFu, maxCycles = 0;
  double cycleSum = 0.0;

  // aquecimento (estabiliza cache); nao contabilizado
  for (int iteration = 0; iteration < 16; iteration++) {
    varyInputs(iteration, messageLength);
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
  }

  for (int iteration = 0; iteration < iterations; iteration++) {
    varyInputs(iteration, messageLength);

    uint32_t startCycles = ESP.getCycleCount();
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
    uint32_t endCycles = ESP.getCycleCount();

    uint32_t cycles = endCycles - startCycles;

    if (cycles < minCycles) {
      minCycles = cycles;
    }

    if (cycles > maxCycles) {
      maxCycles = cycles;
    }

    cycleSum += (double) cycles;
  }

  CycleStatistics stats;

  stats.minCycles  = minCycles;
  stats.maxCycles  = maxCycles;
  stats.meanCycles = cycleSum / iterations;

  return stats;
}

// ----- AES-128-GCM (mbedTLS; bloco AES por hardware no ESP32) -----
static CycleStatistics benchmarkAES(size_t messageLength, int iterations)
{
  mbedtls_gcm_context gcmContext;
  mbedtls_gcm_init(&gcmContext);
  mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128);  // chave fixada 1x (amortizada)

  uint32_t minCycles = 0xFFFFFFFFu, maxCycles = 0;
  double cycleSum = 0.0;

  // aquecimento (estabiliza cache); nao contabilizado
  for (int iteration = 0; iteration < 16; iteration++) {
    varyInputs(iteration, messageLength);
    mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, messageLength, initializationVector, 12, NULL, 0, plaintext, aesCiphertext, 16, aesTag);
  }

  for (int iteration = 0; iteration < iterations; iteration++) {
    varyInputs(iteration, messageLength);

    uint32_t startCycles = ESP.getCycleCount();
    mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, messageLength, initializationVector, 12, NULL, 0, plaintext, aesCiphertext, 16, aesTag);
    uint32_t endCycles = ESP.getCycleCount();

    uint32_t cycles = endCycles - startCycles;

    if (cycles < minCycles) {
      minCycles = cycles;
    }

    if (cycles > maxCycles) {
      maxCycles = cycles;
    }

    cycleSum += (double) cycles;
  }

  mbedtls_gcm_free(&gcmContext);

  CycleStatistics stats;

  stats.minCycles  = minCycles;
  stats.maxCycles  = maxCycles;
  stats.meanCycles = cycleSum / iterations;

  return stats;
}

static void printComparison(size_t messageLength, CycleStatistics asconStats, CycleStatistics aesStats)
{
  Serial.print("  "); Serial.print((unsigned) messageLength); Serial.print(" B  ");
  Serial.print("Ascon: "); Serial.print(asconStats.minCycles); Serial.print(" cic (~"); Serial.print(cyclesToMicroseconds(asconStats.minCycles), 2); Serial.print(" us)");
  Serial.print("  |  AES-GCM: "); Serial.print(aesStats.minCycles); Serial.print(" cic (~"); Serial.print(cyclesToMicroseconds(aesStats.minCycles), 2); Serial.print(" us)");
  Serial.print("  |  razao AES/Ascon: "); Serial.println((double) aesStats.minCycles / (double) asconStats.minCycles, 2);
}

void setup()
{
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.println("=== Comparativo Ascon-128a (sw) vs AES-128-GCM (hw) ===");
  Serial.print("CPU: "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
  Serial.println();

  // ----- Sanidade: o caminho AES-GCM realmente cifra e a tag valida -----
  varyInputs(7, 32);
  {
    mbedtls_gcm_context gcmContext;
    mbedtls_gcm_init(&gcmContext);
    int setkeyResult  = mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128);
    int encryptResult = mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, 32, initializationVector, 12, NULL, 0, plaintext, aesCiphertext, 16, aesTag);
    uint8_t decryptedOutput[MAX_PLAINTEXT];
    int decryptResult = mbedtls_gcm_auth_decrypt(&gcmContext, 32, initializationVector, 12, NULL, 0, aesTag, 16, aesCiphertext, decryptedOutput);
    mbedtls_gcm_free(&gcmContext);
    bool sanityPassed = (setkeyResult == 0 && encryptResult == 0 && decryptResult == 0 && memcmp(decryptedOutput, plaintext, 32) == 0);
    Serial.print("Sanidade AES-GCM: "); Serial.println(sanityPassed ? "OK (cifra/decifra/tag validam)" : "FALHOU");
  }
  Serial.println();

  // ----- Memoria: heap por operacao -----
  Serial.println("[Memoria - heap por operacao]");
  varyInputs(1, 16);
  size_t ciphertextLength = 0;
  uint32_t heapBeforeAscon = ESP.getFreeHeap();
  ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, 16, NULL, 0, nonce, key);
  uint32_t heapAfterAscon = ESP.getFreeHeap();
  Serial.print("  Ascon-128a: delta heap "); Serial.print((int32_t) heapAfterAscon - (int32_t) heapBeforeAscon); Serial.println(" B (esperado 0)");

  uint32_t heapBeforeAES    = ESP.getFreeHeap();
  uint32_t minHeapBeforeAES = ESP.getMinFreeHeap();
  {
    mbedtls_gcm_context gcmContext;
    mbedtls_gcm_init(&gcmContext);
    mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128);
    mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, 16, initializationVector, 12, NULL, 0, plaintext, aesCiphertext, 16, aesTag);
    mbedtls_gcm_free(&gcmContext);
  }
  uint32_t heapAfterAES    = ESP.getFreeHeap();
  uint32_t minHeapAfterAES = ESP.getMinFreeHeap();
  Serial.print("  AES-GCM: delta heap apos free "); Serial.print((int32_t) heapAfterAES - (int32_t) heapBeforeAES);
  Serial.print(" B | pico transitorio "); Serial.print((int32_t) minHeapBeforeAES - (int32_t) minHeapAfterAES); Serial.println(" B");
  Serial.println();

  // ----- Latencia (minimo = piso livre de interrupcao) -----
  Serial.println("[Latencia de cifragem - minimo de ciclos]");
  printComparison(16, benchmarkAscon(16, 2000), benchmarkAES(16, 2000));
  printComparison(32, benchmarkAscon(32, 2000), benchmarkAES(32, 2000));
  printComparison(64, benchmarkAscon(64, 2000), benchmarkAES(64, 2000));
  Serial.println();

  Serial.println(">>> Comparativo concluido <<<");
}

void loop()
{
  delay(1000);  // roda uma vez no setup(); cede o processador
}
