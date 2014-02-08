/*

  Copyright (c) 2012 Samuel Lidén Borell <samuel@kodafritt.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

#include "../common/defines.h"
#include "platform.h"

#if ENABLE_PKCS11
const char *prefs_pkcs11_module = DEFAULT_PKCS11_MODULE;
#endif
const char *prefs_bankid_emulatedversion = NULL;

/**
 * Loads the preferences from ~/.config/fribid/config
 */
void prefs_load(void) {
    PlatformConfig *cfg = platform_openConfig("fribid", "config");
    if (cfg) {
        char *s;
        /* Which PKCS#11 module to use */
#if ENABLE_PKCS11
        if (platform_getConfigString(cfg, "pkcs11", "module", &s)) {
            prefs_pkcs11_module = s;
        }
#endif
        
        /* Which BankID client software version to report */
        if (platform_getConfigString(cfg, "expiry", "version-to-emulate", &s)) {
            prefs_bankid_emulatedversion = s;
        }
        
        platform_freeConfig(cfg);
    }
}


