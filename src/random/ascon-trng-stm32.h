/*
 * Copyright (C) 2022 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef ASCON_TRNG_STM32_H
#define ASCON_TRNG_STM32_H

#if defined(USE_HAL_DRIVER)

/* STM32 platform with the HAL libraries.  Try to detect the chip family.
 * Unfortunately there is no single header or define for "STM32 with an RNG".
 * Patches welcome to extend this list to new STM32 platforms.
 *
 * For each chip family we link to the .h file that contains the
 * up to date list of #define's for that family.  Some of them
 * don't have an RNG which will be caught later when we check for
 * the HAL_RNG_MODULE_ENABLED define.  It is easier to list
 * everything and not risk missing one.
 *
 * The list of defines for each family will need to be updated periodically. */
/* https://github.com/STMicroelectronics/STM32CubeF2/blob/master/Drivers/CMSIS/Device/ST/STM32F2xx/Include/stm32f2xx.h */
#if defined(STM32F205xx) || defined(STM32F215xx) || defined(STM32F207xx) || \
    defined(STM32F217xx)
#include "stm32f2xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeF4/blob/master/Drivers/CMSIS/Device/ST/STM32F4xx/Include/stm32f4xx.h */
#elif defined(STM32F405xx) || defined(STM32F415xx) || defined(STM32F407xx) || \
      defined(STM32F417xx) || defined(STM32F427xx) || defined(STM32F437xx) || \
      defined(STM32F429xx) || defined(STM32F439xx) || defined(STM32F401xC) || \
      defined(STM32F401xE) || defined(STM32F410Tx) || defined(STM32F410Cx) || \
      defined(STM32F410Rx) || defined(STM32F411xE) || defined(STM32F446xx) || \
      defined(STM32F469xx) || defined(STM32F479xx) || defined(STM32F412Cx) || \
      defined(STM32F412Zx) || defined(STM32F412Rx) || defined(STM32F412Vx) || \
      defined(STM32F413xx) || defined(STM32F423xx)
#include "stm32f4xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeF7/blob/master/Drivers/CMSIS/Device/ST/STM32F7xx/Include/stm32f7xx.h */
#elif defined(STM32F722xx) || defined(STM32F723xx) || defined(STM32F732xx) || \
      defined(STM32F733xx) || defined(STM32F756xx) || defined(STM32F746xx) || \
      defined(STM32F745xx) || defined(STM32F765xx) || defined(STM32F767xx) || \
      defined(STM32F769xx) || defined(STM32F777xx) || defined(STM32F779xx) || \
      defined(STM32F730xx) || defined(STM32F750xx)
#include "stm32f7xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeG0/blob/master/Drivers/CMSIS/Device/ST/STM32G0xx/Include/stm32g0xx.h */
#elif defined(STM32G0B1xx) || defined(STM32G0C1xx) || defined(STM32G0B0xx) || \
      defined(STM32G071xx) || defined(STM32G081xx) || defined(STM32G070xx) || \
      defined(STM32G031xx) || defined(STM32G041xx) || defined(STM32G030xx) || \
      defined(STM32G051xx) || defined(STM32G061xx) || defined(STM32G050xx)
#include "stm32g0xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeG4/blob/master/Drivers/CMSIS/Device/ST/STM32G4xx/Include/stm32g4xx.h */
#elif defined(STM32G431xx) || defined(STM32G441xx) || defined(STM32G471xx) || \
      defined(STM32G473xx) || defined(STM32G483xx) || defined(STM32G474xx) || \
      defined(STM32G484xx) || defined(STM32G491xx) || defined(STM32G4A1xx) || \
      defined(STM32GBK1CB)
#include "stm32g4xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeH7/blob/master/Drivers/CMSIS/Device/ST/STM32H7xx/Include/stm32h7xx.h */
#elif defined(STM32H743xx) || defined(STM32H753xx) || defined(STM32H750xx) || \
      defined(STM32H742xx) || defined(STM32H745xx) || defined(STM32H745xG) || \
      defined(STM32H755xx) || defined(STM32H747xx) || defined(STM32H747xG) || \
      defined(STM32H757xx) || defined(STM32H7B0xx) || defined(STM32H7B0xxQ) || \
      defined(STM32H7A3xx) || defined(STM32H7B3xx) || defined(STM32H7A3xxQ) || \
      defined(STM32H7B3xxQ) || defined(STM32H735xx) || defined(STM32H733xx) || \
      defined(STM32H730xx) || defined(STM32H730xxQ) || defined(STM32H725xx) || \
      defined(STM32H723xx)
#include "stm32h7xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeL0/blob/master/Drivers/CMSIS/Device/ST/STM32L0xx/Include/stm32l0xx.h */
#elif defined(STM32L010xB) || defined(STM32L010x8) || defined(STM32L010x6) || \
      defined(STM32L010x4) || defined(STM32L011xx) || defined(STM32L021xx) || \
      defined(STM32L031xx) || defined(STM32L041xx) || defined(STM32L051xx) || \
      defined(STM32L052xx) || defined(STM32L053xx) || defined(STM32L062xx) || \
      defined(STM32L063xx) || defined(STM32L071xx) || defined(STM32L072xx) || \
      defined(STM32L073xx) || defined(STM32L082xx) || defined(STM32L083xx) || \
      defined(STM32L081xx)
#include "stm32l0xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeL4/blob/master/Drivers/CMSIS/Device/ST/STM32L4xx/Include/stm32l4xx.h */
#elif defined(STM32L412xx) || defined(STM32L422xx) || defined(STM32L431xx) || \
      defined(STM32L432xx) || defined(STM32L433xx) || defined(STM32L442xx) || \
      defined(STM32L443xx) || defined(STM32L451xx) || defined(STM32L452xx) || \
      defined(STM32L462xx) || defined(STM32L471xx) || defined(STM32L475xx) || \
      defined(STM32L476xx) || defined(STM32L485xx) || defined(STM32L486xx) || \
      defined(STM32L496xx) || defined(STM32L4A6xx) || defined(STM32L4P5xx) || \
      defined(STM32L4Q5xx) || defined(STM32L4R5xx) || defined(STM32L4R7xx) || \
      defined(STM32L4R9xx) || defined(STM32L4S5xx) || defined(STM32L4S7xx) || \
      defined(STM32L4S9xx)
#include "stm32l4xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeL5/blob/master/Drivers/CMSIS/Device/ST/STM32L5xx/Include/stm32l5xx.h */
#elif defined(STM32L552xx) || defined(STM32L562xx)
#include "stm32l5xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeWB/blob/master/Drivers/CMSIS/Device/ST/STM32WBxx/Include/stm32wbxx.h */
#elif defined(STM32WB55xx) || defined(STM32WB5Mxx) || defined(STM32WB50xx) || \
      defined(STM32WB35xx) || defined(STM32WB30xx) || defined(STM32WB15xx) || \
      defined(STM32WB10xx)
#include "stm32wbxx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeWL/blob/main/Drivers/CMSIS/Device/ST/STM32WLxx/Include/stm32wlxx.h */
#elif defined(STM32WL55xx) || defined(STM32WLE5xx) || defined(STM32WL54xx) || \
      defined(STM32WLE4xx) || defined(STM32WL5Mxx)
#include "stm32wlxx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeU5/blob/main/Drivers/CMSIS/Device/ST/STM32U5xx/Include/stm32u5xx.h */
#elif defined(STM32U575xx) || defined(STM32U585xx) || defined(STM32U595xx) || \
      defined(STM32U599xx) || defined(STM32U5A5xx) || defined(STM32U5A9xx)
#include "stm32u5xx_hal.h"
#define ASCON_TRNG_STM32 hrng
/* https://github.com/STMicroelectronics/STM32CubeMP1/blob/master/Drivers/CMSIS/Device/ST/STM32MP1xx/Include/stm32mp1xx.h */
#elif defined(STM32MP15xx) || defined(STM32MP157Axx) || \
      defined(STM32MP157Cxx) || defined(STM32MP157Dxx) || \
      defined(STM32MP157Fxx) || defined(STM32MP153Axx) || \
      defined(STM32MP153Cxx) || defined(STM32MP153Dxx) || \
      defined(STM32MP153Fxx) || defined(STM32MP151Axx) || \
      defined(STM32MP151Cxx) || defined(STM32MP151Dxx) || \
      defined(STM32MP151Fxx)
#include "stm32mp1xx_hal.h"
#define ASCON_TRNG_STM32 hrng1 /* MP1 series has two RNG's, use the first one */
#endif

#if defined(HAL_RNG_MODULE_ENABLED)
#define ASCON_TRNG_STM32_ENABLED 1
#else
/* Using HAL libraries on STM32, but the RNG has not been selected
 * in the configuration.  Use STM32Cube to fix this and recompile. */
#define ASCON_TRNG_NONE 1
#define ASCON_TRNG_MIXER 1
#endif

#endif /* USE_HAL_DRIVER */

#endif
