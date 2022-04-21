
This directory contains interfaces to the system's random number source,
or "True Random Number Generator" (TRNG).  The TRNG code is very
system-specific and will probably need work to port the TRNG API
to new embedded microcontrollers.  Patches welcome.

The specific implementation is selected by ascon-select-trng.h.
You may need to modify the #ifdef's in this file for your system.

User applications should use the <ascon/random.h> API instead.
