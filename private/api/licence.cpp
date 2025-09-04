#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#include <string>
#include <api/rtti.hpp>
#include <api/licence.hpp>
#include <api/ntp.hpp>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#include <base64.h>

#pragma comment(lib, "wldap32.lib" )
#pragma comment(lib, "crypt32.lib" )
#pragma comment(lib, "Ws2_32.lib")

using namespace CTU::VIN::NTP_client;
std::unique_ptr<licence::protection> licence::protection::instance = nullptr;

static void rc4(const unsigned char* key, const unsigned char* input, size_t input_len, unsigned char* output) {

    int i, j = 0;
    unsigned char S[256], K[256];

    for (i = 0; i < 256; ++i) {

        S[i] = i;
        K[i] = key[i % strlen((const char*)key)];
    }

    for (i = 0; i < 256; ++i) {

        j = (j + S[i] + K[i]) % 256;
        std::swap(S[i], S[j]);
    }

    i = j = 0;
    for (size_t k = 0; k < input_len; ++k) {

        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        unsigned char rand_byte = S[(S[i] + S[j]) % 256];
        output[k] = input[k] ^ rand_byte;
    }
}

std::string licence::protection::string_base64_decode(const std::string& in) {

    std::string out;
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(in.c_str(), in.length());
    bmem = BIO_push(bio, bmem);

    char buffer[1024];
    int decoded_length = 0;
    while ((decoded_length = BIO_read(bmem, buffer, 1024)) > 0) out.append(buffer, decoded_length);

    BIO_free_all(bmem);
    return out;
}

std::vector<unsigned char> licence::protection::byte_base64_decode(const std::string& in) {

    BIO* bio, * b64;
    int decodeLen = in.length();
    std::vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(in.data(), static_cast<int>(in.length()));
    bio = BIO_push(b64, bio);

    int decodedLen = BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
    if (decodedLen < 0) decodedLen = 0;
    buffer.resize(decodedLen);

    BIO_free_all(bio);
    return buffer;
}

std::string licence::protection::base64_encode(const unsigned char* input, size_t len) {

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* bio = BIO_push(b64, mem);

    BIO_write(bio, input, static_cast<int>(len));
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return encoded;
}

std::string licence::protection::rc4_decode(const std::string& base64_input, const std::string& licence) {

    std::vector<unsigned char> rc4_key;
    for (size_t i = 0; i < 16; i += 2) rc4_key.push_back(static_cast<unsigned char>(licence[i]));
    rc4_key[8] = '\0';
    if (rc4_key.size() != 8) return "";
    std::vector<unsigned char> decoded_b64 = byte_base64_decode(base64_input);
    if (decoded_b64.empty()) return "";
    std::vector<unsigned char> output(decoded_b64.size());
    rc4(rc4_key.data(), decoded_b64.data(), decoded_b64.size(), output.data());
    std::string session_key(output.begin(), output.end());
    return session_key;
}

static std::string hex_to_bytes(const std::string& hex) {

    std::string bytes;
    StringSource(hex, true, new HexDecoder(new StringSink(bytes)));
    return bytes;
}

std::string licence::protection::decrypt_string(const std::string& encrypted_string_base64, const std::string& chacha_key_hex, const std::string& rabbit_key_hex, const std::string& nonce_hex) {
    
    try {

        std::string chacha_key = hex_to_bytes(chacha_key_hex);
        std::string rabbit_key = hex_to_bytes(rabbit_key_hex);
        std::string nonce = hex_to_bytes(nonce_hex);

        if (chacha_key.size() != 32 || rabbit_key.size() != 16 || nonce.size() != 12)
            return "";

        std::string rabbit_ciphertext;
        StringSource ss1(encrypted_string_base64, true,
            new Base64Decoder(new StringSink(rabbit_ciphertext)));

        std::string chacha_base64;
        Rabbit::Decryption rabbit;
        rabbit.SetKey((const byte*)rabbit_key.data(), rabbit_key.size());

        StringSource ss2(rabbit_ciphertext, true,
            new StreamTransformationFilter(rabbit, new StringSink(chacha_base64)));

        std::string chacha_ciphertext;
        StringSource ss3(chacha_base64, true,
            new Base64Decoder(new StringSink(chacha_ciphertext)));

        std::string plaintext;
        ChaChaTLS::Decryption chacha;
        chacha.SetKeyWithIV((const byte*)chacha_key.data(), chacha_key.size(),
            (const byte*)nonce.data(), nonce.size());

        StringSource ss4(chacha_ciphertext, true,
            new StreamTransformationFilter(chacha, new StringSink(plaintext)));

        return plaintext;

    }
    catch (const CryptoPP::Exception& e) { return ""; }
}

std::string licence::protection::decrypt_aes(const std::string& b64_input, const std::string& session_key) {

    if (session_key.size() != 32) return "";

    std::vector<unsigned char> decoded = byte_base64_decode(b64_input);
    if (decoded.size() <= 16) return "";

    unsigned char iv[16];
    memcpy(iv, decoded.data(), 16);

    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(decoded.data() + 16);
    int ciphertext_len = static_cast<int>(decoded.size() - 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(session_key.data()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    int out_len1 = 0, out_len2 = 0;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(out_len1 + out_len2);
    return std::string(plaintext.begin(), plaintext.end());
}

std::string licence::protection::encrypt_aes(const std::string& plaintext, const std::string& session_key) {

    if (session_key.size() != 32) return "";

    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(session_key.data()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int max_out_len = plaintext.size() + EVP_MAX_BLOCK_LENGTH;
    std::vector<unsigned char> ciphertext(max_out_len);

    int out_len1 = 0;
    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int out_len2 = 0;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    EVP_CIPHER_CTX_free(ctx);

    int ciphertext_len = out_len1 + out_len2;
    ciphertext.resize(ciphertext_len);

    std::vector<unsigned char> final_output;
    final_output.insert(final_output.end(), iv, iv + 16);
    final_output.insert(final_output.end(), ciphertext.begin(), ciphertext.end());

    return base64_encode(final_output.data(), final_output.size());
}

std::string licence::protection::sha256(const char* str) {

    unsigned char hash[SHA256_DIGEST_LENGTH] = { 0 };
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, str, strlen(str));
    SHA256_Final(hash, &sha256_ctx);

    std::stringstream ss;
    for (int n = 0; n < SHA256_DIGEST_LENGTH; ++n) ss << std::setw(2) << std::setfill('0') << std::hex << (int)hash[n];
    return ss.str();
}

uint32_t mulberry32(uint32_t& state) {
    uint32_t t = state += 0x6D2B79F5;
    t = (t ^ (t >> 15)) * (t | 1);
    t ^= t + (t ^ (t >> 7)) * (t | 61);
    return t ^ (t >> 14);
}

uint32_t hash_string(const std::string& str) {
    uint32_t hash = 5381;
    for (char c : str) hash = ((hash << 5) + hash) + (uint8_t)c;
    return hash;
}

std::pair<int, std::string> get_string_from_map(const std::string& str_map, const std::string& seed_str, int desired_index) {

    std::vector<size_t> start_positions;
    size_t pos = 0;
    start_positions.push_back(0);
    const std::string delim = "__";
    
    while ((pos = str_map.find(delim, pos)) != std::string::npos) {
        start_positions.push_back(pos + delim.length());
        pos += delim.length();
    }

    int n = static_cast<int>(start_positions.size());
    if (desired_index < 0 || desired_index >= n) return { 0, "" };

    std::vector<int> index_map(n);
    for (int i = 0; i < n; ++i) index_map[i] = i;

    uint32_t state = hash_string(seed_str);
    for (int i = n - 1; i > 0; --i) {
        uint32_t r = mulberry32(state);
        int j = r % (i + 1);
        std::swap(index_map[i], index_map[j]);
    }

    int segment_index = -1;
    for (int i = 0; i < n; ++i) {
        if (index_map[i] == desired_index) {
            segment_index = i;
            break;
        }
    }

    if (segment_index == -1) return { 0, "" };

    size_t start = start_positions[segment_index];
    size_t end = (segment_index + 1 < n)
        ? start_positions[segment_index + 1] - delim.length()
        : std::string::npos;

    return { segment_index, str_map.substr(start, end - start) };
}

std::string licence::protection::decrypt_string(int index) {

    std::pair<int, std::string> info = get_string_from_map(this->enc_str_list, std::string(this->licence_uuid), index);
    if (info.second == "") return "";
    return decrypt_string(info.second,
        this->chacha_keys[info.first],
        this->rabbit_keys[info.first],
        this->nonce_list[info.first]);
}

// Credits To & Taken from: https://gist.github.com/mmozeiko/c0dfcc8fec527a90a02145d2cc0bfb6d
int licence::protection::tls_connect(tls_socket* s, const char* hostname, unsigned short port) {

    s->sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->sock == INVALID_SOCKET) return -1;

    char sport[64];
    wnsprintfA(sport, sizeof(sport), "%u", port);

    if (!WSAConnectByNameA(s->sock, hostname, sport, NULL, NULL, NULL, NULL, NULL, NULL)) {
        closesocket(s->sock);
        return -1;
    }

    {
        SCHANNEL_CRED cred = { 0 };
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.dwFlags = SCH_USE_STRONG_CRYPTO
            | SCH_CRED_AUTO_CRED_VALIDATION
            | SCH_CRED_NO_DEFAULT_CREDS;
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2;

        if (AcquireCredentialsHandleA(NULL, (char*)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &s->handle, NULL) != SEC_E_OK)
        {
            closesocket(s->sock);
            return -1;
        }
    }

    s->received = s->used = s->available = 0;
    s->decrypted = NULL;

    // perform tls handshake
    // 1) call InitializeSecurityContext to create/update schannel context
    // 2) when it returns SEC_E_OK - tls handshake completed
    // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
    // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
    // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
    // 6) otherwise read data from server and go to step 1

    CtxtHandle* context = NULL;
    int result = 0;
    for (;;)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s->incoming;
        inbuffers[0].cbBuffer = s->received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS sec = InitializeSecurityContextA(
            &s->handle,
            context,
            context ? NULL : (SEC_CHAR*)hostname,
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &s->context,
            &outdesc,
            &flags,
            NULL);

        context = &s->context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            MoveMemory(s->incoming, s->incoming + (s->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            s->received = inbuffers[1].cbBuffer;
        }
        else
        {
            s->received = 0;
        }

        if (sec == SEC_E_OK)
        {
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            result = -1;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED)
        {
            char* buffer = (char*)outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0)
            {
                int d = send(s->sock, buffer, size, 0);
                if (d <= 0)
                {
                    break;
                }
                size -= d;
                buffer += d;
            }
            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
            {
                result = -1;
                break;
            }
        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE)
        {
            // SEC_E_CERT_EXPIRED - certificate expired or revoked
            // SEC_E_WRONG_PRINCIPAL - bad hostname
            // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
            // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
            result = -1;
            break;
        }

        if (s->received == sizeof(s->incoming))
        {
            result = -1;
            break;
        }

        int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
        if (r == 0)
        {
            return 0;
        }
        else if (r < 0)
        {
            result = -1;
            break;
        }
        s->received += r;
    }

    if (result != 0)
    {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        return result;
    }

    HCERTSTORE cert_store = NULL;
    PCCERT_CONTEXT cert = NULL;

    if (QueryContextAttributes(context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID*)&cert) != SEC_E_OK || !cert) {

        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        return -1;

    }

    uint8_t cert_hash[32];
    unlock_cert_hash(cert_hash);

    try {

        std::string cert_bytes(reinterpret_cast<const char*>(cert->pbCertEncoded), cert->cbCertEncoded);
        std::string cert_sha256 = sha256(cert_bytes.c_str());

        // NOTE: Added this part so we can pin the SSL certificate of the BetterTelegram Server to the DLL statically
        if (cert_sha256 != "80608c52ac65acc04705251848823c016355abda3205ed0d56a075f520a32428") {

            CertFreeCertificateContext(cert);
            DeleteSecurityContext(context);
            FreeCredentialsHandle(&s->handle);
            closesocket(s->sock);
            return -1;

        }

        CertFreeCertificateContext(cert);

    } catch (...) {

        if (cert) CertFreeCertificateContext(cert);

        DeleteSecurityContext(context);
        FreeCredentialsHandle(&s->handle);
        closesocket(s->sock);
        return -1;

    }

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
    return 0;
}

void licence::protection::tls_disconnect(tls_socket* s)
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&s->context, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = (char*)outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(s->sock, buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }
    shutdown(s->sock, SD_BOTH);

    DeleteSecurityContext(&s->context);
    FreeCredentialsHandle(&s->handle);
    closesocket(s->sock);
}

int licence::protection::tls_write(tls_socket* s, const void* buffer, int size)
{
    while (size != 0)
    {
        int use = my_min(size, s->sizes.cbMaximumMessage);

        char wbuffer[TLS_MAX_PACKET_SIZE];
        assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = s->sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
        buffers[2].cbBuffer = s->sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
        if (sec != SEC_E_OK)
        {
            // this should not happen, but just in case check it
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total)
        {
            int d = send(s->sock, wbuffer + sent, total - sent, 0);
            if (d <= 0)
            {
                // error sending data to socket, or server disconnected
                return -1;
            }
            sent += d;
        }

        buffer = (char*)buffer + use;
        size -= use;
    }

    return 0;
}

int licence::protection::tls_read(tls_socket* s, void* buffer, int size)
{
    int result = 0;

    while (size != 0)
    {
        if (s->decrypted)
        {
            // if there is decrypted data available, then use it as much as possible
            int use = my_min(size, s->available);
            CopyMemory(buffer, s->decrypted, use);
            buffer = (char*)buffer + use;
            size -= use;
            result += use;

            if (use == s->available)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                s->received -= s->used;
                s->used = 0;
                s->available = 0;
                s->decrypted = NULL;
            }
            else
            {
                s->available -= use;
                s->decrypted += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (s->received != 0)
            {
                SecBuffer buffers[4];
                assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = s->incoming;
                buffers[0].cbBuffer = s->received;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {
                    assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                    assert(buffers[1].BufferType == SECBUFFER_DATA);
                    assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                    s->decrypted = (char*)buffers[1].pvBuffer;
                    s->available = buffers[1].cbBuffer;
                    s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    s->received = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    /* TLS1.3 repurposed status code */
                    assert(buffers[3].BufferType == SECBUFFER_EXTRA); // TLS<1.3 server wants to renegotiate TLS connection, not implemented here
                    assert(((BYTE*)buffers[3].pvBuffer)[5] == 0x04); // new_session_ticket
                    SecBuffer inbuffers[2] = { 0 };
                    inbuffers[0].BufferType = SECBUFFER_TOKEN;
                    inbuffers[0].pvBuffer = buffers[3].pvBuffer;
                    inbuffers[0].cbBuffer = buffers[3].cbBuffer;
                    inbuffers[1].BufferType = SECBUFFER_EMPTY;

                    SecBuffer outbuffers[3] = { 0 };
                    outbuffers[0].BufferType = SECBUFFER_TOKEN;
                    outbuffers[1].BufferType = SECBUFFER_ALERT;
                    outbuffers[2].BufferType = SECBUFFER_EMPTY;

                    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
                    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

                    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT
                        | ISC_REQ_STREAM | ISC_RET_EXTENDED_ERROR;
                    SECURITY_STATUS sec = InitializeSecurityContext(
                        &s->handle,
                        &s->context,
                        NULL,
                        flags,
                        0,
                        0,
                        &indesc,
                        0,
                        NULL,
                        &outdesc,
                        &flags,
                        NULL);
                    assert(inbuffers[1].BufferType == SECBUFFER_EXTRA);
                    s->used = s->received - inbuffers[1].cbBuffer;
                    MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
                    s->received -= s->used;
                    continue;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (s->received == sizeof(s->incoming))
            {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }

            // wait for more ciphertext data from server
            int r = recv(s->sock, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                // error receiving data from socket
                result = -1;
                break;
            }
            s->received += r;
        }
    }

    return result;
}

// NOTE: this is my custom time-based OTP algorithm, a similar algorithm is implemented on the servers-
int generate_totp(const std::string& key, uint64_t epoch_time, int step = 30, int digits = 6) {

    uint64_t counter = epoch_time / step;

    unsigned char counter_bytes[8];
    for (int i = 7; i >= 0; --i) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    unsigned char hmac_result[SHA_DIGEST_LENGTH];
    unsigned int hmac_length = SHA_DIGEST_LENGTH;
    HMAC(EVP_sha1(), key.c_str(), key.length(), counter_bytes, 8, hmac_result, &hmac_length);

    int offset = hmac_result[hmac_length - 1] & 0x0F;
    uint32_t binary_code =
        ((hmac_result[offset] & 0x7F) << 24) |
        ((hmac_result[offset + 1] & 0xFF) << 16) |
        ((hmac_result[offset + 2] & 0xFF) << 8) |
        (hmac_result[offset + 3] & 0xFF);

    return binary_code % static_cast<uint32_t>(pow(10, digits));
}

// Reference, this uses NTP Lib from: 
std::string licence::protection::generate_timebased_OTP(const std::string& session_key) {
    HNTP ntp_client = Client__create();
    if (!ntp_client) return "";

    struct Result* result = nullptr;
    enum Status status = Client__query(ntp_client, "time.windows.com", &result);
    if (status != OK || !result) {
        Client__close(ntp_client);
        return "";
    }
    
    std::tm tm{};
    tm.tm_year = result->time.tm_year - 1900;
    tm.tm_mon = result->time.tm_mon - 1;
    tm.tm_mday = result->time.tm_mday;
    tm.tm_hour = result->time.tm_hour;
    tm.tm_min = result->time.tm_min;
    tm.tm_sec = result->time.tm_sec;

    int otp = generate_totp(session_key, static_cast<uint64_t>(_mkgmtime(&tm)));

    Client__free_result(result);
    Client__close(ntp_client);

    char otp_str[7];
    sprintf(otp_str, "%06d", otp);

    return std::string(otp_str);
}

nlohmann::json licence::protection::send_get_request(const std::string& url, const std::string& session_key) {

    tls_socket s;
    nlohmann::json response_json = nullptr;

    size_t host_start = url.find("://");
    if (host_start != std::string::npos) host_start += 3;

    size_t host_end = url.find("/", host_start);
    std::string hostname = url.substr(host_start, host_end - host_start);
    std::string path = url.substr(host_end);

    std::string TOTP = generate_timebased_OTP(session_key);
    if (TOTP == "") return response_json;

    if (tls_connect(&s, hostname.c_str(), 443) != 0) return response_json;

    std::string request = "GET " + path + " HTTP/1.1\r\n";
    request += "X-Session-Key: " + TOTP + "\r\n";
    request += "Host: " + hostname + "\r\n";
    request += "Connection: close\r\n\r\n";
    
    if (tls_write(&s, request.c_str(), request.length()) != 0) {
        tls_disconnect(&s);
        return response_json;
    }

    int bytes_received = 0;
    char response[1024] = { 0 };
    std::string encrypted_response_data;
    while ((bytes_received = tls_read(&s, response, 1023)) > 0) {
        encrypted_response_data.append(response, bytes_received);
        memset(response, 0, 1024);
    }
    
    try {
        size_t crlf = encrypted_response_data.find("\r\n\r\n");
        std::string decrypted_response_data = decrypt_aes(crlf != std::string::npos ? encrypted_response_data.substr(crlf + 4) : "", session_key);
        if (decrypted_response_data == "") return response_json;
        response_json = nlohmann::json::parse(decrypted_response_data);
    }
    catch (const nlohmann::json::parse_error& e) {}

    tls_disconnect(&s);
    return response_json;
}

nlohmann::json licence::protection::send_post_request(const std::string& url, const nlohmann::json& post_data, const std::string& session_key) {

    tls_socket s;
    nlohmann::json response_json;

    size_t host_start = url.find("://");
    if (host_start != std::string::npos) host_start += 3;

    size_t host_end = url.find("/", host_start);
    std::string hostname = url.substr(host_start, host_end - host_start);
    std::string path = url.substr(host_end);

    if (tls_connect(&s, hostname.c_str(), 443) != 0)
        return response_json;

    std::string aes_encoded = encrypt_aes(post_data.dump(), session_key);

    std::string TOTP = generate_timebased_OTP(session_key);
    if (TOTP == "") return response_json;

    std::string request = "POST " + path + " HTTP/1.1\r\n";
    request += "Host: " + hostname + "\r\n";
    request += "X-Session-Key: " + TOTP + "\r\n";
    request += "Content-Type: text/html\r\n";
    request += "Content-Length: " + std::to_string(aes_encoded.size()) + "\r\n";
    request += "Connection: close\r\n\r\n";
    request += aes_encoded;

    if (tls_write(&s, request.c_str(), request.length()) != 0) {
        tls_disconnect(&s);
        return response_json;
    }

    int bytes_received = 0;
    char response[1024] = { 0 };

    std::string encrypted_response_data;
    while ((bytes_received = tls_read(&s, response, 1023)) > 0) {
        encrypted_response_data.append(response, bytes_received);
        memset(response, 0, 1024);
    }

    try { 
        size_t crlf = encrypted_response_data.find("\r\n\r\n");
        std::string decrypted_response_data = decrypt_aes(crlf != std::string::npos ? encrypted_response_data.substr(crlf + 4) : "", session_key);
        if (decrypted_response_data == "") return response_json;
        response_json = nlohmann::json::parse(decrypted_response_data);
    }
    catch (const nlohmann::json::parse_error& e) {}

    tls_disconnect(&s);
    return response_json;
}