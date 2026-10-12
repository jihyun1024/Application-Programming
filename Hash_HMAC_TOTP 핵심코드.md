# 해시, HMAC, TOTP 핵심 코드


이 문서는 [src/crypto.c](src/crypto.c)와 [src/totp.c](src/totp.c)에 구현된 해시·메시지 인증 코드와 TOTP 계산의 핵심을 발췌합니다.


## SHA-256과 HMAC-SHA256


SHA-256은 입력 데이터의 고정 길이 다이제스트를 계산합니다. HMAC-SHA256은 비밀 키와 메시지를 함께 사용해 인증 코드를 만듭니다. 둘 다 OpenSSL의 EVP/HMAC API를 사용하며, 성공 여부와 결과 길이도 확인합니다.


```c

int crypto_sha256(const void *data, size_t length,

                  unsigned char digest[SHA256_SIZE])

{

    unsigned int digest_length = 0;


    return EVP_Digest(data, length, digest, &digest_length,

                      EVP_sha256(), NULL) == 1 &&

           digest_length == SHA256_SIZE;

}


int crypto_hmac_sha256(const void *key, size_t key_length,

                       const void *data, size_t data_length,

                       unsigned char digest[SHA256_SIZE])

{

    unsigned int digest_length = 0;


    return HMAC(EVP_sha256(), key, (int)key_length, data, data_length,

                digest, &digest_length) != NULL &&

           digest_length == SHA256_SIZE;

}

```


SHA-256은 비밀번호 확인용 해시 등에서 사용되고, HMAC-SHA256은 로그인 비밀번호를 키로 `vault.dat` 전체에 대해 계산하는 무결성 값 출력에 사용됩니다. 일반 해시는 키를 사용하지 않지만, HMAC은 키를 사용해 메시지 인증 값을 계산한다는 차이가 있습니다.


## 비교, 메모리 정리, 16진수 변환


```c

int crypto_equal(const unsigned char *left, const unsigned char *right,

                 size_t length)

{

    unsigned char difference = 0;


    for (size_t i = 0; i < length; ++i) {

        difference |= (unsigned char)(left[i] ^ right[i]);

    }

    return difference == 0;

}


void crypto_clear(void *data, size_t length)

{

    volatile unsigned char *bytes = (volatile unsigned char *)data;


    while (length-- > 0) {

        *bytes++ = 0;

    }

}


void crypto_to_hex(const unsigned char *bytes, size_t length, char *hex)

{

    static const char digits[] = "0123456789abcdef";


    for (size_t i = 0; i < length; ++i) {

        hex[i * 2] = digits[bytes[i] >> 4];

        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];

    }

    hex[length * 2] = '\0';

}

```


`crypto_equal()`은 다른 바이트를 발견해도 즉시 반환하지 않고 지정된 길이까지 비교합니다. `crypto_clear()`는 `volatile` 포인터를 통해 임시 비밀 데이터를 0으로 덮고, `crypto_to_hex()`는 바이너리 다이제스트를 저장 가능한 소문자 16진수 문자열로 바꿉니다.


## TOTP 비밀 키 생성


```c

#define TOTP_STEP_SECONDS 30

#define TOTP_SECRET_BYTES 20


int totp_generate_secret(char secret[TOTP_SECRET_MAX])

{

    unsigned char random_bytes[TOTP_SECRET_BYTES];


    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {

        return 0;

    }

    base32_encode(random_bytes, sizeof(random_bytes), secret);

    crypto_clear(random_bytes, sizeof(random_bytes));

    return 1;

}

```


OpenSSL의 암호학적 난수 생성기로 20바이트 비밀 키를 만들고 인증 앱이 입력할 수 있도록 Base32로 인코딩합니다. 생성 뒤에는 임시 바이트 배열을 지웁니다.


## TOTP 코드 계산


```c

int totp_generate_code(const char *secret, unsigned long long time_step,

                       char code[TOTP_CODE_SIZE])

{

    unsigned char key[64];

    unsigned char counter[8];

    unsigned char digest[EVP_MAX_MD_SIZE];

    size_t key_length = 0;

    unsigned int digest_length = 0;


    if (!base32_decode(secret, key, sizeof(key), &key_length)) {

        return 0;

    }

    for (int i = 7; i >= 0; --i) {

        counter[i] = (unsigned char)(time_step & 0xff);

        time_step >>= 8;

    }

    if (HMAC(EVP_sha1(), key, (int)key_length, counter, sizeof(counter),

             digest, &digest_length) == NULL || digest_length < 20) {

        crypto_clear(key, sizeof(key));

        return 0;

    }


    unsigned int offset = digest[digest_length - 1] & 0x0f;

    uint32_t binary = ((uint32_t)(digest[offset] & 0x7f) << 24) |

                      ((uint32_t)digest[offset + 1] << 16) |

                      ((uint32_t)digest[offset + 2] << 8) |

                      (uint32_t)digest[offset + 3];

    snprintf(code, TOTP_CODE_SIZE, "%06u", binary % 1000000U);


    crypto_clear(key, sizeof(key));

    crypto_clear(digest, sizeof(digest));

    return 1;

}

```


Base32 비밀 키를 바이트 배열로 복원하고, 시간 카운터를 8바이트 big-endian으로 만든 뒤 HMAC-SHA1을 계산합니다. HMAC 결과의 마지막 nibble로 시작 위치를 정하는 동적 절단을 적용하고, 결과를 0을 포함한 6자리 십진수로 제한합니다. 설정은 30초 주기이며 RFC 6238의 TOTP 계산 방식입니다.


## 현재 코드 검증


```c

unsigned long long current_step = (unsigned long long)now / TOTP_STEP_SECONDS;

for (int offset = -window; offset <= window; ++offset) {

    unsigned long long step = current_step;

    if (offset < 0) {

        if (step < (unsigned long long)(-offset)) {

            continue;

        }

        step -= (unsigned long long)(-offset);

    } else {

        step += (unsigned long long)offset;

    }


    char candidate_otp[TOTP_CODE_SIZE];

    if (totp_generate_code(secret, step, candidate_otp) &&

        strcmp(candidate_otp, user_otp) == 0) {

        return 1;

    }

}

```


시간 오차를 허용하기 위해 현재 시간 구간과 `window`만큼 앞뒤 구간의 코드를 확인합니다. 로그인에서는 `window`를 1로 전달하므로 최대 세 구간을 검사합니다. 입력은 먼저 6자리 숫자인지 확인합니다.


## 인증 앱 등록 URI 생성


`totp_make_uri()`는 인증 앱이 계정을 등록할 때 읽는 `otpauth://` URI를 만듭니다. 계정 이름은 URI에서 안전하게 표현되도록 영문자·숫자 및 `-._~` 외의 바이트를 퍼센트 인코딩하고, 출력 버퍼의 크기를 넘으면 실패를 반환합니다.


```c

int totp_make_uri(const char *account, const char *secret,

                  char *uri, size_t uri_size)

{

    static const char hex[] = "0123456789ABCDEF";

    int written = snprintf(uri, uri_size, "otpauth://totp/PasswordManager:");


    if (written < 0 || (size_t)written >= uri_size) {

        return 0;

    }

    size_t used = (size_t)written;

    for (size_t i = 0; account[i] != '\0'; ++i) {

        unsigned char ch = (unsigned char)account[i];

        int unreserved = (ch >= 'A' && ch <= 'Z') ||

                         (ch >= 'a' && ch <= 'z') ||

                         (ch >= '0' && ch <= '9') ||

                         ch == '-' || ch == '.' || ch == '_' || ch == '~';

        size_t needed = unreserved ? 1 : 3;


        if (used + needed >= uri_size) {

            return 0;

        }

        if (unreserved) {

            uri[used++] = (char)ch;

        } else {

            uri[used++] = '%';

            uri[used++] = hex[ch >> 4];

            uri[used++] = hex[ch & 0x0f];

        }

    }


    written = snprintf(uri + used, uri_size - used,

                       "?secret=%s&issuer=PasswordManager&algorithm=SHA1"

                       "&digits=6&period=%d", secret, TOTP_STEP_SECONDS);

    return written >= 0 && (size_t)written < uri_size - used;

}

```


URI의 `secret`은 Base32 TOTP 비밀 키, `issuer`는 서비스 이름, `algorithm`은 HMAC-SHA1, `digits`는 코드 자릿수, `period`는 코드가 바뀌는 주기(30초)를 지정합니다. 이 함수는 등록 URI만 생성하며 QR 이미지는 만들지 않습니다.

