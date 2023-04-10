
// This sketch demonstrates how to generate random numbers on an Arduino
// device, including sampling a transistor noise source from an analog input.
//
// AVR platforms use EEPROM to save the random seed across a loss of power.
// Arduino Due stores the random seed in the last page of flash memory.
//
// This example is placed into the public domain.

#include <ASCON.h>
#include "TransistorNoise.h"
#if defined(__AVR__)
#include <EEPROM.h>
// AVR-based Arduinos
#define HAVE_SEED_STORAGE 1
#define HAVE_EEPROM_SEED_STORAGE 1
#elif defined (__arm__) && defined (__SAM3X8E__)
// Arduino Due
#define HAVE_SEED_STORAGE 1
#define HAVE_DUE_SEED_STORAGE 1
#endif

#define TIMEOUT_SECS(n) (((unsigned long)(n)) * 1000)
#define TIMEOUT_MINS(n) (TIMEOUT_SECS(n) * 60)

#define RESEED_TIMEOUT TIMEOUT_SECS(1)
#define SAVE_TIMEOUT TIMEOUT_MINS(5)

static ascon_random_state_t prng;
static TransistorNoise noise(A1);
static bool have_system_trng;
static bool calibrating;
static unsigned long reseed_timer;
static unsigned long save_timer;

#ifdef HAVE_EEPROM_SEED_STORAGE

// Read data from EEPROM.
static int eeprom_storage_read
    (const ascon_storage_t *storage, size_t offset,
     unsigned char *data, size_t size)
{
    if (offset >= storage->size || size > (storage->size - offset))
        return -1;
    for (size_t index = 0; index < size; ++index)
        data[index] = EEPROM.read(storage->address + offset + index);
    return size;
}

// Write data to EEPROM.
static int eeprom_storage_write
    (const ascon_storage_t *storage, size_t offset,
     const unsigned char *data, size_t size, int erase)
{
    if (offset >= storage->size || size > (storage->size - offset))
        return -1;
    if (data) {
        for (size_t index = 0; index < size; ++index)
            EEPROM.update(storage->address + offset + index, data[index]);
    } else if (erase) {
        for (size_t index = 0; index < size; ++index)
            EEPROM.update(storage->address + offset + index, 0xFF);
    }
    return size;
}

// Definition of the non-volatile storage on this system.
static ascon_storage_t storage = {
    .page_size = 1,
    .erase_size = 0,
    .address = 0,
    .size = ASCON_RANDOM_SAVED_SEED_SIZE,
    .partial_writes = 0,
    .read = eeprom_storage_read,
    .write = eeprom_storage_write
};

#elif defined(HAVE_DUE_SEED_STORAGE)

// Find the flash memory of interest.  Allow for the possibility
// of other SAM-based Arduino variants in the future.
#if defined(IFLASH1_ADDR)
#define RNG_FLASH_ADDR      IFLASH1_ADDR
#define RNG_FLASH_SIZE      IFLASH1_SIZE
#define RNG_FLASH_PAGE_SIZE IFLASH1_PAGE_SIZE
#define RNG_EFC             EFC1
#elif defined(IFLASH0_ADDR)
#define RNG_FLASH_ADDR      IFLASH0_ADDR
#define RNG_FLASH_SIZE      IFLASH0_SIZE
#define RNG_FLASH_PAGE_SIZE IFLASH0_PAGE_SIZE
#define RNG_EFC             EFC0
#else
#define RNG_FLASH_ADDR      IFLASH_ADDR
#define RNG_FLASH_SIZE      IFLASH_SIZE
#define RNG_FLASH_PAGE_SIZE IFLASH_PAGE_SIZE
#define RNG_EFC             EFC
#endif

// Address of the flash page to use for saving the seed on the Due.
// All SAM variants have a page size of 256 bytes or greater so there is
// plenty of room for the 32 byte seed in the last page of flash memory.
#define RNG_SEED_ADDR (RNG_FLASH_ADDR + RNG_FLASH_SIZE - RNG_FLASH_PAGE_SIZE)
#define RNG_SEED_PAGE ((RNG_FLASH_SIZE / RNG_FLASH_PAGE_SIZE) - 1)

// Erases the flash page containing the seed and then writes the new seed.
// It is assumed the seed has already been loaded into the latch registers.
__attribute__((section(".ramfunc")))
static void erase_and_write_seed()
{
    // Execute the "Erase and Write Page" command.
    RNG_EFC->EEFC_FCR = (0x5A << 24) | (RNG_SEED_PAGE << 8) | EFC_FCMD_EWP;

    // Wait for the FRDY bit to be raised.
    while ((RNG_EFC->EEFC_FSR & EEFC_FSR_FRDY) == 0)
        ;   // do nothing until FRDY rises.
}

// Read data from flash memory.
static int sam3x_flash_storage_read
    (const ascon_storage_t *storage, size_t offset,
     unsigned char *data, size_t size)
{
    if (offset >= storage->size || size > (storage->size - offset))
        return -1;
    memcpy(data, (const unsigned char *)(RNG_SEED_ADDR + offset), size);
    return size;
}

// Write data to flash memory.
static int sam3x_flash_storage_write
    (const ascon_storage_t *storage, size_t offset,
     const unsigned char *data, size_t size, int erase)
{
    if (offset >= storage->size || size > (storage->size - offset))
        return -1;
    if (data) {
        // We assume that there is only one page, so the offset can be ignored.
        // Prepare the data to be written as an array of 32-bit words.
        unsigned posn;
        for (posn = 0; posn < (size / sizeof(uint32_t)); ++posn) {
            uint32_t x;
            memcpy(&x, data + posn * sizeof(uint32_t), sizeof(uint32_t));
            ((uint32_t *)RNG_SEED_ADDR)[posn] = x;
        }
        for (; posn < (RNG_FLASH_PAGE_SIZE / 4); ++posn) {
            ((uint32_t *)RNG_SEED_ADDR)[posn] = 0xFFFFFFFFU;
        }
        erase_and_write_seed();
    } else if (erase) {
        // Erase the entire page.
        for (unsigned posn = 0; posn < (RNG_FLASH_PAGE_SIZE / 4); ++posn) {
            ((uint32_t *)RNG_SEED_ADDR)[posn] = 0xFFFFFFFFU;
        }
        erase_and_write_seed();
    }
    return size;
}

// Definition of the non-volatile storage on the Arduino Due.
static ascon_storage_t storage = {
    .page_size = RNG_FLASH_PAGE_SIZE,
    .erase_size = RNG_FLASH_PAGE_SIZE,
    .address = RNG_FLASH_ADDR + RNG_FLASH_SIZE - RNG_FLASH_PAGE_SIZE,
    .size = RNG_FLASH_PAGE_SIZE,
    .partial_writes = 0,
    .read = sam3x_flash_storage_read,
    .write = sam3x_flash_storage_write
};

#endif // HAVE_DUE_SEED_STORAGE

static void print_hex(const byte *data, unsigned len)
{
    static char const hexchars[] = "0123456789ABCDEF";
    unsigned long time = millis();
    Serial.print(time / 1000);
    Serial.print('.');
    Serial.print((time / 100) % 10);
    Serial.print(": ");
    while (len > 0) {
        int b = *data++;
        Serial.print(hexchars[(b >> 4) & 0x0F]);
        Serial.print(hexchars[b & 0x0F]);
        --len;
    }
    Serial.println();
}

static void generate_output()
{
    unsigned char data[32];
    ascon_random_fetch(&prng, data, sizeof(data));
    print_hex(data, sizeof(data));
}

void setup()
{
    Serial.begin(9600);
    Serial.println();

    // Initialise the PRNG and get some initial entropy from the
    // system random number source.  If we don't have one, then
    // fall back to entropy collection from the noise source only.
    have_system_trng = (ascon_random_init(&prng) != 0);
    calibrating = false;

    // Load the previously-saved PRNG seed from the end of EEPROM.
#ifdef HAVE_EEPROM_SEED_STORAGE
    storage.address = EEPROM.length() - storage.size;
#endif
#ifdef HAVE_SEED_STORAGE
    ascon_random_load_seed(&prng, &storage);
#endif

    // Start the timers.
    reseed_timer = millis();
    save_timer = millis();
}

void loop()
{
    // Sample the noise source and stir the entropy into the PRNG.
    noise.stir(&prng);

    // Reseed the PRNG from the system random number source once a second.
    bool onesec = false;
    if ((millis() - reseed_timer) >= RESEED_TIMEOUT) {
        reseed_timer = millis();
        ascon_random_reseed(&prng);
        onesec = true;
    }

    // Generate output from the PRNG.
    if (have_system_trng) {
        // Generate data once a second if we have a system random number source.
        if (onesec) {
            generate_output();
        }
    } else {
        // Generate output whenever we have 32 bytes of entropy if
        // all we have to work with is a noise source.
        if (noise.haveCredits(32)) {
            generate_output();
        }

        // Print the noise source's calibration state whenever it changes.
        bool cal = noise.calibrating();
        if (calibrating != cal) {
            calibrating = cal;
            if (calibrating)
                Serial.println("noise source is calibrating");
            else
                Serial.println("noise source is calibrated");
        }
    }

#ifdef HAVE_SEED_STORAGE
    // Save the seed if the save timer has expired.
    if ((millis() - save_timer) >= SAVE_TIMEOUT) {
        save_timer = millis();
        ascon_random_save_seed(&prng, &storage);
    }
#endif
}
