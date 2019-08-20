
/*
 * Copyright (c) 2006-2018 RT-Thread Development Team. All rights reserved.
 * License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "certs.h"

const char mbedtls_root_certificate[] = 
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\r\n" \
"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n" \
"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\r\n" \
"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\r\n" \
"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n" \
"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\r\n" \
"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\r\n" \
"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\r\n" \
"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\r\n" \
"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\r\n" \
"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\r\n" \
"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\r\n" \
"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\r\n" \
"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\r\n" \
"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\r\n" \
"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\r\n" \
"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\r\n" \
"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\r\n" \
"-----END CERTIFICATE-----\r\n" \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDbzCCAlcCCQD4QkcZervB9zANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJj\r\n" \
"bjELMAkGA1UECAwCYmoxCzAJBgNVBAcMAmN5MQ8wDQYDVQQKDAZkcmFnb24xDDAK\r\n" \
"BgNVBAsMA3p3eDEPMA0GA1UEAwwGb3duX2NhMRwwGgYJKoZIhvcNAQkBFg10ZXN0\r\n" \
"QHRlc3QuY29tMB4XDTE5MDgxOTAyMDgwNFoXDTIwMDgxODAyMDgwNFowfjELMAkG\r\n" \
"A1UEBhMCY24xCzAJBgNVBAgMAmJqMQswCQYDVQQHDAJjeTEPMA0GA1UECgwGZHJh\r\n" \
"Z29uMQwwCgYDVQQLDAN6d3gxGDAWBgNVBAMMDzE5Mi4xNjguMTg4LjE0NjEcMBoG\r\n" \
"CSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP\r\n" \
"ADCCAQoCggEBAMH919PqNprxSGiBGbaXX6F+37SaMsdtQjw9ISrVi8KJBj1lHPx2\r\n" \
"YLhy4JGwtN8HWxjfQ5RWjeaW4Udi4RZU5583cr3lkCLJyP/VtHN1jS9nC4D3/k19\r\n" \
"QNC/YC1bjZZ2fVS0wLXwZnDTz9YIS13DrnFyrhu75f5c4c6cn4s9Ia5ANrTj63Ac\r\n" \
"u7BZKGPss3HvFFoL/1BTitbs4HF1ceKI6ALm9peQNiQOpyLmVgdIzUR+2rjKZHDh\r\n" \
"qLgTABkTg2wAYgfFHo6h8sMwc/DIu7MfW5jg3NCsNkwjv3I/TL2M2J6P6vZnQdid\r\n" \
"npkr7g5Py1MTGxn5g44goAncp8qV8TL5/yUCAwEAATANBgkqhkiG9w0BAQsFAAOC\r\n" \
"AQEAQ350ICpi9cQsOic1BE/mVP63xmCj99gFUZ6IO4mXCdoASd/fBmhaU4M85MF7\r\n" \
"23hrEXz7307w6bYPkBFXf5fku42HVBxfTxoahnqaqRqFNTLjXxGr0Kzzr7DX3vSk\r\n" \
"EGdjyopaSksdgTVWjVoEz5mfHr/G8T+Q7GmTSoMjje+qJUEg9CHZIcRBIrj+S56B\r\n" \
"zg+astl6PhN2COlOKENDnJpcnvhjhjoDhLrbC7H48CMknkHLU0MWLEneWWI1hkew\r\n" \
"bKGC8S+pMkPXJ41evBExtF6BEuD89ARwLuhnVF6tZHRf+cdw9oZnXQ86H/4nTv0m\r\n" \
"OOxxBMgu/9BpIbVoxD4nIyufLw==\r\n" \
"-----END CERTIFICATE-----\r\n" \

;

const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);

