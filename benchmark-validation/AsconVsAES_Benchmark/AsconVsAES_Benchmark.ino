/*
 * AsconVsAES_Benchmark -- Comparativo software x hardware (Cap. 2 / Secao 3.4.3).
 *
 *   Ascon-128a   : criptografia leve em SOFTWARE (biblioteca ascon-suite).
 *   AES-128-GCM  : via mbedTLS. No ESP32 classico, o BLOCO AES roda no
 *                  acelerador de HARDWARE, mas o GHASH (autenticacao) e em
 *                  software (o GCM em hardware so existe no S2/S3/C3).
 *
 * Mede, sob as MESMAS condicoes (mesma run, 240 MHz):
 *   - latencia de cifragem (ciclos de clock) em 16/32/64 B;
 *   - uso de heap por operacao.
 *
 * Metodologia da medicao de tempo: como o driver de AES por hardware adquire um
 * mutex (proibido dentro de secao critica), NAO desabilitamos interrupcoes aqui.
 * Para uma comparacao justa, reportamos o MINIMO de ciclos (piso livre de
 * interrupcao) de ambos, alem da media.
 *
 * APIs: ascon128a_aead_encrypt (ascon-suite, MIT) e mbedtls_gcm_* (mbedTLS).
 */

#include <ASCON.h>
#include "mbedtls/gcm.h"
#include <string.h>

#define MAXPT 64

static uint8_t key[16];
static uint8_t nonce[16];        // nonce do Ascon (16 B)
static uint8_t iv[12];           // IV do GCM (12 B = 96 bits, caso nativo/rapido)
static uint8_t pt[MAXPT];
static uint8_t ct[MAXPT + 16];   // Ascon: ciphertext || tag
static uint8_t aesOut[MAXPT];    // AES: ciphertext
static uint8_t aesTag[16];       // AES: tag

struct CycleStats { uint32_t min; uint32_t max; double mean; };

// Varia chave/nonce/iv/pt a cada iteracao (tamanho fixo).
static void varyInputs(int it, size_t mlen)
{
  for (int i = 0; i < 16; i++) { key[i] = (uint8_t)(it*31 + i*7 + 1); nonce[i] = (uint8_t)(it*17 + i*3); }
  for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(it*19 + i*5);
  for (size_t i = 0; i < mlen; i++) pt[i] = (uint8_t)(it*13 + i*5);
}

static double cyclesToUs(double c) { return c / (double) getCpuFrequencyMhz(); }

// ----- Ascon-128a (software) -----
static CycleStats benchAscon(size_t mlen, int iters)
{
  size_t clen = 0; uint32_t mn = 0xFFFFFFFFu, mx = 0; double sum = 0.0;
  for (int it = 0; it < 16; it++) { varyInputs(it, mlen); ascon128a_aead_encrypt(ct, &clen, pt, mlen, NULL, 0, nonce, key); }
  for (int it = 0; it < iters; it++) {
    varyInputs(it, mlen);
    uint32_t t0 = ESP.getCycleCount();
    ascon128a_aead_encrypt(ct, &clen, pt, mlen, NULL, 0, nonce, key);
    uint32_t t1 = ESP.getCycleCount();
    uint32_t c = t1 - t0;
    if (c < mn) mn = c; if (c > mx) mx = c; sum += (double) c;
  }
  CycleStats s; s.min = mn; s.max = mx; s.mean = sum / iters; return s;
}

// ----- AES-128-GCM (mbedTLS; bloco AES por hardware no ESP32) -----
static CycleStats benchAES(size_t mlen, int iters)
{
  mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);  // chave fixada 1x (amortizada)
  uint32_t mn = 0xFFFFFFFFu, mx = 0; double sum = 0.0;
  for (int it = 0; it < 16; it++) { varyInputs(it, mlen); mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, mlen, iv, 12, NULL, 0, pt, aesOut, 16, aesTag); }
  for (int it = 0; it < iters; it++) {
    varyInputs(it, mlen);
    uint32_t t0 = ESP.getCycleCount();
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, mlen, iv, 12, NULL, 0, pt, aesOut, 16, aesTag);
    uint32_t t1 = ESP.getCycleCount();
    uint32_t c = t1 - t0;
    if (c < mn) mn = c; if (c > mx) mx = c; sum += (double) c;
  }
  mbedtls_gcm_free(&gcm);
  CycleStats s; s.min = mn; s.max = mx; s.mean = sum / iters; return s;
}

static void printCompare(size_t mlen, CycleStats a, CycleStats e)
{
  Serial.print("  "); Serial.print((unsigned) mlen); Serial.print(" B  ");
  Serial.print("Ascon: "); Serial.print(a.min); Serial.print(" cic (~"); Serial.print(cyclesToUs(a.min), 2); Serial.print(" us)");
  Serial.print("  |  AES-GCM: "); Serial.print(e.min); Serial.print(" cic (~"); Serial.print(cyclesToUs(e.min), 2); Serial.print(" us)");
  Serial.print("  |  razao AES/Ascon: "); Serial.println((double) e.min / (double) a.min, 2);
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
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int e1 = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 128);
    int e2 = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, 32, iv, 12, NULL, 0, pt, aesOut, 16, aesTag);
    uint8_t dec[MAXPT];
    int e3 = mbedtls_gcm_auth_decrypt(&g, 32, iv, 12, NULL, 0, aesTag, 16, aesOut, dec);
    mbedtls_gcm_free(&g);
    bool ok = (e1 == 0 && e2 == 0 && e3 == 0 && memcmp(dec, pt, 32) == 0);
    Serial.print("Sanidade AES-GCM: "); Serial.println(ok ? "OK (cifra/decifra/tag validam)" : "FALHOU");
  }
  Serial.println();

  // ----- Memoria: heap por operacao -----
  Serial.println("[Memoria - heap por operacao]");
  varyInputs(1, 16);
  size_t clen = 0;
  uint32_t a0 = ESP.getFreeHeap();
  ascon128a_aead_encrypt(ct, &clen, pt, 16, NULL, 0, nonce, key);
  uint32_t a1 = ESP.getFreeHeap();
  Serial.print("  Ascon-128a: delta heap "); Serial.print((int32_t) a1 - (int32_t) a0); Serial.println(" B (esperado 0)");

  uint32_t h0 = ESP.getFreeHeap();
  uint32_t m0 = ESP.getMinFreeHeap();
  {
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 128);
    mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, 16, iv, 12, NULL, 0, pt, aesOut, 16, aesTag);
    mbedtls_gcm_free(&g);
  }
  uint32_t h1 = ESP.getFreeHeap();
  uint32_t m1 = ESP.getMinFreeHeap();
  Serial.print("  AES-GCM: delta heap apos free "); Serial.print((int32_t) h1 - (int32_t) h0);
  Serial.print(" B | pico transitorio "); Serial.print((int32_t) m0 - (int32_t) m1); Serial.println(" B");
  Serial.println();

  // ----- Latencia (minimo = piso livre de interrupcao) -----
  Serial.println("[Latencia de cifragem - minimo de ciclos]");
  printCompare(16, benchAscon(16, 2000), benchAES(16, 2000));
  printCompare(32, benchAscon(32, 2000), benchAES(32, 2000));
  printCompare(64, benchAscon(64, 2000), benchAES(64, 2000));
  Serial.println();

  Serial.println(">>> Comparativo concluido <<<");
}

void loop()
{
  delay(1000);  // roda uma vez no setup(); cede o processador
}

=== Comparativo Ascon-128a (sw) vs AES-128-GCM (hw) ===
CPU: 240 MHz

Sanidade AES-GCM: OK (cifra/decifra/tag validam)

[Memoria - heap por operacao]
  Ascon-128a: delta heap 0 B (esperado 0)
  AES-GCM: delta heap apos free 0 B | pico transitorio 0 B

[Latencia de cifragem - minimo de ciclos]
  16 B  Ascon: 6115 cic (~25.48 us)  |  AES-GCM: 8541 cic (~35.59 us)  |  razao AES/Ascon: 1.40
  32 B  Ascon: 7212 cic (~30.05 us)  |  AES-GCM: 10650 cic (~44.38 us)  |  razao AES/Ascon: 1.48
  64 B  Ascon: 9406 cic (~39.19 us)  |  AES-GCM: 14868 cic (~61.95 us)  |  razao AES/Ascon: 1.58

>>> Comparativo concluido <<<