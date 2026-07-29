#include <ASCON.h>
#include <string.h>

#define MAX_BUFFER 96

static const uint8_t key[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

static const uint8_t nonce[16] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const uint8_t plaintext[]      = "temp=23.5C;lux=00812;batt=98"; // payload
static const uint8_t associatedData[] = "devEUI=42fb8334;fcnt=00128";   // cabecalho LoRaWAN

static const size_t plaintextLength      = sizeof(plaintext) - 1;       // -1: ignora o terminador '\0'
static const size_t associatedDataLength = sizeof(associatedData) - 1;

static uint8_t validCiphertext[MAX_BUFFER];  // ciphertext || tag do pacote valido
static size_t  ciphertextLength = 0;

struct Result {
  int tested;
  int rejected;
};

// Decifra (ciphertext, associatedData) e diz se foi CORRETAMENTE REJEITADO
// (tag invalida -> decryptResult < 0).
static bool decryptRejected(const uint8_t *ciphertext, size_t ciphertextLength,
                            const uint8_t *associatedData, size_t associatedDataLength)
{
  uint8_t decryptOutput[MAX_BUFFER];
  size_t  messageLength = 0;

  int decryptResult = ascon128a_aead_decrypt(decryptOutput, &messageLength,
                                             ciphertext, ciphertextLength,
                                             associatedData, associatedDataLength,
                                             nonce, key);

  return decryptResult < 0;
}

// Vira cada bit da regiao [rangeStart, rangeEnd) do buffer (ciphertext || tag)
// e confere a rejeicao.
static Result flipCiphertextRegion(size_t rangeStart, size_t rangeEnd)
{
  Result result = {0, 0};
  uint8_t tampered[MAX_BUFFER];

  for (size_t byteIndex = rangeStart; byteIndex < rangeEnd; byteIndex++) {
    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
      memcpy(tampered, validCiphertext, ciphertextLength);
      tampered[byteIndex] ^= (uint8_t)(1 << bitIndex);
      result.tested++;

      if (decryptRejected(tampered, ciphertextLength, associatedData, associatedDataLength)) {
        result.rejected++;
      }
    }
  }

  return result;
}

// Vira cada bit dos dados associados e confere a rejeicao (ciphertext intacto).
static Result flipAssociatedData()
{
  Result result = {0, 0};
  uint8_t tamperedAssociatedData[MAX_BUFFER];

  for (size_t byteIndex = 0; byteIndex < associatedDataLength; byteIndex++) {
    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
      memcpy(tamperedAssociatedData, associatedData, associatedDataLength);
      tamperedAssociatedData[byteIndex] ^= (uint8_t)(1 << bitIndex);
      result.tested++;

      if (decryptRejected(validCiphertext, ciphertextLength, tamperedAssociatedData, associatedDataLength)) {
        result.rejected++;
      }
    }
  }

  return result;
}

void setup()
{
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("=== Ascon-128a AEAD bit-flipping (Secao 3.4.2) ===");

  // (1) Gera um pacote valido.
  ascon128a_aead_encrypt(validCiphertext, &ciphertextLength,
                         plaintext, plaintextLength,
                         associatedData, associatedDataLength,
                         nonce, key);

  Serial.print("Pacote valido: ");
  Serial.print((unsigned) plaintextLength);      Serial.print(" B de texto claro + ");
  Serial.print((unsigned) associatedDataLength); Serial.print(" B de AD -> ");
  Serial.print((unsigned) ciphertextLength);     Serial.println(" B (ciphertext || tag)");

  // (2) Controle: o pacote intacto deve ser ACEITO e recuperar o texto claro.
  uint8_t decryptOutput[MAX_BUFFER];
  size_t  messageLength = 0;

  int decryptResult = ascon128a_aead_decrypt(decryptOutput, &messageLength,
                                             validCiphertext, ciphertextLength,
                                             associatedData, associatedDataLength,
                                             nonce, key);

  bool controlPassed = (decryptResult >= 0) &&
                       (messageLength == plaintextLength) &&
                       (memcmp(decryptOutput, plaintext, plaintextLength) == 0);

  Serial.print("Controle (pacote intacto): ");

  if (controlPassed) {
    Serial.println("ACEITO, texto claro recuperado (OK)");
  }
  else {
    Serial.println("FALHOU (inesperado)");
  }

  Serial.println();

  // (3) Tres frentes de adulteracao: cada bit virado deve ser REJEITADO.
  Serial.println("Adulteracao por bit-flipping (cada bit deve ser REJEITADO):");

  Result ciphertextResult = flipCiphertextRegion(0, plaintextLength);   // texto cifrado
  Serial.print("  Ciphertext : ");
  Serial.print(ciphertextResult.rejected); Serial.print("/"); Serial.print(ciphertextResult.tested);
  Serial.println(" rejeitados");

  Result associatedDataResult = flipAssociatedData();                   // dados associados
  Serial.print("  AD         : ");
  Serial.print(associatedDataResult.rejected); Serial.print("/"); Serial.print(associatedDataResult.tested);
  Serial.println(" rejeitados");

  Result tagResult = flipCiphertextRegion(plaintextLength, ciphertextLength);  // tag (ultimos 16 B)
  Serial.print("  Tag        : ");
  Serial.print(tagResult.rejected); Serial.print("/"); Serial.print(tagResult.tested);
  Serial.println(" rejeitados");

  int totalTested   = ciphertextResult.tested   + associatedDataResult.tested   + tagResult.tested;
  int totalRejected = ciphertextResult.rejected + associatedDataResult.rejected + tagResult.rejected;

  Serial.println();
  Serial.print("Total: ");
  Serial.print(totalRejected); Serial.print("/"); Serial.print(totalTested);
  Serial.println(" adulteracoes de 1 bit rejeitadas");

  if (controlPassed && totalRejected == totalTested) {
    Serial.println(">>> AEAD OK: pacote intacto aceito, toda adulteracao rejeitada <<<");
  }
  else {
    Serial.println(">>> FALHA: ver acima <<<");
  }
}

void loop()
{
  delay(1000);
}
