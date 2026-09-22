#include "pch.h"
#include <iostream>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <experimental/filesystem>
#include <fstream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include "HTMLParserBase.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <set>
#include <unordered_set>
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

#define INITIAL_BUF_SIZE 4096
#define THRESHOLD 1024
#define READ_TIMEOUT 5

queue<string> pendingQueue;
mutex queueMutex;

atomic<int> extracted(0);
atomic<int> hostPassed(0);
atomic<int> dnsPassed(0);
atomic<int> ipPassed(0);
atomic<int> robotsPassed(0);
atomic<int> crawled(0);
atomic<long long> linksFound(0);
atomic<bool> crawlingDone(false);
atomic<long long> downloaded(0);
atomic<int> threads(0);
atomic<int> http2(0);
atomic<int> http3(0);
atomic<int> http4(0);
atomic<int> http5(0);
atomic<int> other(0);
atomic<int> tamu(0);
atomic<long long> outsidetamu(0);
atomic<bool> oneinput(false);

SSL_CTX* g_ctx = nullptr;

void warn() {
    cout << "incorrect input" << endl;
    cout << "input must be in the form of - example.txt" << endl;
    cout << "scheme must be http or https" << endl;
}

set<string> seenips;
set<string> seenhosts;
mutex seenMutex;


class Socket {

public:
    SOCKET sock; // socket handle
    SSL* ssl = nullptr; // non-null when this connection is TLS-wrapped (https)
    char* buf; // current buffer
    int allocatedSize; // bytes allocated for buf
    int curPos; // current position in buffer

    bool Read(bool robots);
    Socket();

    void SetSock(SOCKET s) {
        sock = s;
    }
    void SetSSL(SSL* s) {
        ssl = s;
    }
    char* GetBuffer() {
        return buf;
    }
    int GetSize() {
        return curPos;
    }
};
Socket::Socket()
{
    // create this buffer once, then possibly reuse for multiple connections in Part 3
    buf = (char*)malloc(INITIAL_BUF_SIZE); // either new char [INITIAL_BUF_SIZE] or malloc (INITIAL_BUF_SIZE)
    allocatedSize = INITIAL_BUF_SIZE;
    curPos = 0;
    sock = -1;

}
bool Socket::Read(bool robots = false)
{
    // set timeout to 10 seconds
    while (true)
    {
        if (ssl != nullptr && SSL_pending(ssl) > 0)
        {
            int bytes = SSL_read(ssl, buf + curPos, allocatedSize - curPos - 1);
            if (bytes <= 0) {
                int sslErr = SSL_get_error(ssl, bytes);
                if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                buf[curPos] = '\0';
                return true;
            }

            curPos += bytes;

            if (robots && curPos > 18 * 1024) {
                return false;
            }
            if (curPos > 2 * 1024 * 1024) {
                return false;
            }
            if (allocatedSize - curPos < THRESHOLD) {
                int newSize = allocatedSize * 2;
                char* newBuf = (char*)realloc(buf, newSize);
                if (newBuf == nullptr) {
                    fprintf(stderr, "realloc failed\n");
                    return false;
                }
                buf = newBuf;
                allocatedSize = newSize;
            }
            continue; // loop back and check SSL_pending() again before touching select()
        }

        fd_set fd;
        FD_ZERO(&fd);
        FD_SET(sock, &fd);

        timeval timeout;
        timeout.tv_sec = READ_TIMEOUT;
        timeout.tv_usec = 0;

        int ret;
        // wait to see if socket has any data (see MSDN)
        if ((ret = select(0, &fd, nullptr, nullptr, &timeout)) > 0)
        {
            int bytes;

            if (ssl != nullptr) {
                // TLS connection - read decrypted application data
                bytes = SSL_read(ssl, buf + curPos, allocatedSize - curPos - 1);
                if (bytes <= 0) {
                    int sslErr = SSL_get_error(ssl, bytes);
                    if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {

                        continue;
                    }
                    buf[curPos] = '\0';
                    return true;
                }
            }
            else {
                // plaintext HTTP
                bytes = recv(sock, buf + curPos, allocatedSize - curPos - 1, 0);
                if (bytes == SOCKET_ERROR) {
                    // print WSAGetLastError()
                    //cout << WSAGetLastError() << endl;
                    break;
                }
                if (bytes == 0) {
                    // NULL-terminate buffer
                    buf[curPos] = '\0';
                    return true; // normal completion
                }
            }

            curPos += bytes; // adjust where the next recv/SSL_read goes

            if (robots && curPos > 18 * 1024) {
                //cout << "robots.txt too large - 2kb limit";
                return false;
            }

            if (curPos > 2 * 1024 * 1024) {
                //cout << "memory limit exceeded - 2mb" << endl;
                return false;
            }

            if (allocatedSize - curPos < THRESHOLD) {
                // resize buffer; you can use realloc(), HeapReAlloc(), or
                // memcpy the buffer into a bigger array
                int newSize = allocatedSize * 2;
                char* newBuf = (char*)realloc(buf, newSize);
                if (newBuf == nullptr) {
                    fprintf(stderr, "realloc failed\n");
                    return false;
                }
                buf = newBuf;
                allocatedSize = newSize;
            }
        }
        else if (ret == 0) {
            // report timeout
            //cout << "timeout after 10 seconds" << endl;
            break;
        }
        else {
            // print WSAGetLastError()
            //cout << WSAGetLastError() << endl;
            break;
        }
    }
    return false;
}

// Wraps an already-connected TCP socket in a TLS session (used for https).
// The TCP connect() must already have succeeded before calling this.
// Returns nullptr on failure; caller is still responsible for closesocket().
SSL* tlsConnect(SOCKET sock, const char* host)
{
    SSL* ssl = SSL_new(g_ctx);
    if (ssl == nullptr) {
        return nullptr;
    }

    SSL_set_fd(ssl, (int)sock);

    // Server Name Indication - lets the remote server pick the right
    // certificate when it's hosting more than one HTTPS site.
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        return nullptr;
    }

    return ssl;
}

// Sends 'len' bytes from 'data', transparently using SSL_write when 'ssl'
// is non-null and looping past partial writes either way.
bool sendAll(SOCKET sock, SSL* ssl, const char* data, int len)
{
    int sentTotal = 0;
    while (sentTotal < len) {
        int n;
        if (ssl != nullptr) {
            n = SSL_write(ssl, data + sentTotal, len - sentTotal);
            if (n <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return false;
            }
        }
        else {
            n = send(sock, data + sentTotal, len - sentTotal, 0);
            if (n == SOCKET_ERROR) {
                return false;
            }
        }
        sentTotal += n;
    }
    return true;
}

// Tears down a connection opened by tlsConnect()/plain connect(): shuts
// down and frees the TLS session (if any), then closes the socket.
void closeConnection(SOCKET sock, SSL* ssl)
{
    if (ssl != nullptr) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    closesocket(sock);
}

string extractHost(const char* link)
{
    const char* schemeEnd = strstr(link, "://");
    if (schemeEnd == nullptr) {
        return "";
    }

    const char* hostStart = schemeEnd + 3;
    const char* hostEnd = hostStart;
    while (*hostEnd != '\0' && *hostEnd != '/' && *hostEnd != ':' &&
        *hostEnd != '?' && *hostEnd != '#')
    {
        hostEnd++;
    }

    return string(hostStart, hostEnd - hostStart);
}

bool tamuhost(const string& host)
{
    vector<string> labels;
    size_t start = 0, pos;
    while ((pos = host.find('.', start)) != string::npos) {
        labels.push_back(host.substr(start, pos - start));
        start = pos + 1;
    }
    labels.push_back(host.substr(start));

    if (labels.size() < 2) {
        return false;
    }

    return labels[labels.size() - 2] == "tamu" && labels[labels.size() - 1] == "edu";
}

int crawler(char* input) {

    char url[1024];
    size_t inlen = strlen(input);
    if (inlen >= sizeof(url)) {
        return 1;
    }
    strcpy_s(url, sizeof(url), input);

    char* fragment = nullptr;
    char* query = nullptr;
    char* path = nullptr;
    char* port = nullptr;
    char* host = nullptr;
    char* scheme = nullptr;
    char* p = nullptr;

    //frag
    p = strchr(url, '#');
    if (p != nullptr) {
        fragment = p + 1;
        *p = '\0';
    }

    //queryu
    p = strchr(url, '?');
    if (p != nullptr) {
        query = p + 1;
        *p = '\0';
    }

    //scheme
    p = strstr(url, "://");
    if (p == nullptr) {
        warn();
        return 1;
    }
    *p = '\0';
    scheme = url;
    if (strcmp(scheme, "http") != 0 && strcmp(scheme, "https") != 0) {
        warn();
        return 1;
    }
    char* begin = p + 3;

    //path
    char temp[1024];
    p = strchr(begin, '/');
    if (p != nullptr) {
        strcpy_s(temp, sizeof(temp), p);
        *p = '\0';
        path = temp;
    }

    //port
    p = strchr(begin, ':');
    if (p != nullptr) {
        port = p + 1;
        *p = '\0';
    }

    //host
    host = begin;

    bool https = (strcmp(scheme, "https") == 0);

    string request;
    request += "GET ";

    if (port == nullptr) {
        if (https)
            port = (char*)"443";
        else
            port = (char*)"80";
    }

    if (path != nullptr) {
        request += path;
    }
    else {
        request += "/";
    }

    if (query != nullptr) {
        request += "?";
        request += query;
    }

    request += " HTTP/1.0\r\n";
    request += "Host: ";
    request += host;
    request += "\r\n";
    request += "User-Agent: jasonsCrawler\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";

    if (oneinput) {
        cout << "url: " << input << endl;
        cout << "       Parsing URL... host " << host << ", port " << port << ", request " << (path ? path : "/") << endl;
    }
    //cout << "url: " << input << endl;
    //cout << "       Parsing URL... host " << host << ", port " << port << ", request " << (path ? path : "/") << endl;

    // string pointing to an HTTP server (DNS name or IP)
    char* str = host;
    //char str [] = "128.194.135.72";
    {
        lock_guard<mutex> lock(seenMutex);

        if (oneinput) {
            cout << "       checking host uniqueness... ";
		}
        //cout << "       checking host uniqueness... ";
        auto hostresult = seenhosts.insert(host);
        if (hostresult.second) {
            if (oneinput) {
                cout << "passed" << endl;
            }
            //cout << "passed" << endl;
            hostPassed++;
        }
        else {
            if (oneinput) {
                cout << "failed" << endl;
			}
            //cout << "failed" << endl;
            return 1;
        }
    }
    // open a TCP socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        printf("socket() generated error %d\n", WSAGetLastError());
        return 1;
    }

    // structure used in DNS lookups
    struct hostent* remote;

    // structure for connecting to server
    struct sockaddr_in server;

    // first assume that the string is an IP address
    ULONGLONG dnsstart = GetTickCount64();
    DWORD IP = inet_addr(str);
    if (IP == INADDR_NONE)
    {
        // if not a valid IP, then do a DNS lookup
        if ((remote = gethostbyname(str)) == NULL) {
            //printf("Invalid string: neither FQDN, nor IP address\n");
            return 1;
        }
        else {
            dnsPassed++;
            memcpy((char*)&(server.sin_addr), remote->h_addr, remote->h_length);
        }

    }
    else
    {
        // if a valid IP, directly drop its binary version into sin_addr
        server.sin_addr.S_un.S_addr = IP;
    }
    ULONGLONG dnsend = GetTickCount64() - dnsstart;
    if (oneinput) {
        cout << "       Doing DNS... done in " << dnsend << " ms, found " << inet_ntoa(server.sin_addr) << endl;
	}
    //cout << "       Doing DNS... done in " << dnsend << " ms, found " << inet_ntoa(server.sin_addr) << endl;

    // setup the port # and protocol type
    server.sin_family = AF_INET;
    server.sin_port = htons((u_short)atoi(port));		// host-to-network flips the byte order

    // connect to the server, then (for https) layer TLS on top of the
    // now-connected TCP socket - the handshake can't happen before connect()
    if (oneinput) {
        cout << "     * Connecting on page... ";
    }
    //cout << "     * Connecting on page... ";
    ULONGLONG connectstart = GetTickCount64();

    if (connect(sock, (struct sockaddr*)&server, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
    {
        //printf("Connection error: %d\n", WSAGetLastError());
        closesocket(sock);
        return 1;
    }

    SSL* ssl = nullptr;
    if (https) {
        ssl = tlsConnect(sock, host);
        if (ssl == nullptr) {
            if (oneinput) {
                cout << "TLS handshake failed" << endl;
            }
            //cout << "TLS handshake failed" << endl;
            closesocket(sock);
            return 1;
        }
    }
    ULONGLONG connectend = GetTickCount64() - connectstart;
    if (oneinput) {
        cout << "done in " << connectend << " ms" << endl;
	}
    //cout << "done in " << connectend << " ms" << endl;

    if (oneinput) {
        cout << "       checking ip uniqueness... ";
	}
    //cout << "       checking ip uniqueness... ";
    auto ipresult = seenips.insert(host);
    if (ipresult.second) {
        if (oneinput) {
                cout << "passed" << endl;
		}
        //cout << "passed" << endl;
        ipPassed++;
    }
    else {
        if (oneinput) {
            cout << "failed" << endl;
        }
        //cout << "failed" << endl;
        closeConnection(sock, ssl);
        return 1;
    }

    if (oneinput) {
        cout << "       Checking robots.txt... ";
    }
    //cout << "       Connecting on robots... ";
    ULONGLONG start = GetTickCount64();

    Socket robots;
    SOCKET rs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (rs == INVALID_SOCKET) {
        //cout << "connect fail";
        closeConnection(sock, ssl);
        return 1;
    }
    if (connect(rs, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        //cout << "connect() failed: " << WSAGetLastError() << endl;
        closesocket(rs);
        closeConnection(sock, ssl);
        return 1;
    }

    SSL* robotsSsl = nullptr;
    if (https) {
        robotsSsl = tlsConnect(rs, host);
        if (robotsSsl == nullptr) {
            if (oneinput) {
                cout << "tls handshake failed on robots" << endl;
			}
            closesocket(rs);
            closeConnection(sock, ssl);
            return 1;
        }
    }
    robots.SetSock(rs);
    robots.SetSSL(robotsSsl);

    string roboreq;
    roboreq += "GET /robots.txt HTTP/1.0\r\n";
    roboreq += "Host: ";
    roboreq += host;
    roboreq += "\r\n";
    roboreq += "User-Agent: jasonsCrawler\r\n";
    roboreq += "Connection: close\r\n";
    roboreq += "\r\n";
    if (!sendAll(rs, robotsSsl, roboreq.c_str(), (int)roboreq.length()))
    {
        //cout << "robots req fail" << WSAGetLastError() << endl;
        closeConnection(rs, robotsSsl);
        closeConnection(sock, ssl);
        return 1;
    }

    // actually pull down the robots.txt response before inspecting it
    robots.Read(true);

    if (robots.GetSize() > 18 * 1024) {
        //cout << "robots.txt too large - 2kb limit" << endl;
        closeConnection(rs, robotsSsl);
        closeConnection(sock, ssl);
        return 1;
    }

    char* r = strstr(robots.GetBuffer(), "Disallow:");
    while (r)
    {
        r += strlen("Disallow:");

        while (*r == ' ' || *r == '\t')
            r++;

        char* end = strstr(r, "\r\n");
        if (!end)
            break;

        string disallow(r, end - r);

        if (!disallow.empty() && path != nullptr &&
            strncmp(path, disallow.c_str(), disallow.length()) == 0)
        {
            if (oneinput) {
                cout << "this page can't be crawled cus its listed in robots.txt" << endl;
            }
            //cout << "this page can't be crawled cus its listed in robots.txt" << endl;
            closeConnection(rs, robotsSsl);
            closeConnection(sock, ssl);
            return 1;
        }

        r = strstr(end, "Disallow:");
    }

    ULONGLONG end = GetTickCount64() - start;
    if (oneinput) {
        cout << "done in " << end << " seconds" << endl;
	}
    //cout << "done in " << end << " seconds" << endl;
    robotsPassed++;
    closeConnection(rs, robotsSsl);


    Socket s;
    s.SetSock(sock);
    s.SetSSL(ssl);
    // send HTTP requests here
    if (oneinput) {
        cout << "       loading... ";
	}
    //cout << "       loading... ";
    ULONGLONG loadstart = GetTickCount64();

    if (!sendAll(sock, ssl, request.c_str(), (int)request.size()))
    {
        if (oneinput) {
            cout << "send fail" << endl;
		}
        //cout << WSAGetLastError() << endl;
        closeConnection(sock, ssl);
        return 1;
    }

    if (!s.Read()) {
        if (oneinput) {
            cout << "read fail" << endl;
        }
        //cout << "read fail" << endl;
        closeConnection(sock, ssl);
        return 1;
    }

    downloaded += s.GetSize();
    crawled++;

    ULONGLONG loadend = GetTickCount64() - loadstart;
    char* response = s.GetBuffer();
    int responseSize = s.GetSize();

    if (oneinput) {
        cout << "done in " << loadend << " ms with " << responseSize << " bytes" << endl;
    }
    //cout << "done in " << loadend << " ms with " << responseSize << " bytes" << endl;

    if(oneinput) {
        cout << "       Verifying header... ";
	}
    //cout << "       Verifying header... ";
    int statusCode = 0;
    // status line looks like: HTTP/1.1 200 OK\r\n
    char* statusLineStart = strchr(response, ' ');
    if (statusLineStart != nullptr) {
        statusCode = atoi(statusLineStart + 1);
    }
    if (oneinput) {
        cout << "status code " << statusCode << endl;
    }
    //cout << "status code " << statusCode << endl;


    char* body = strstr(response, "\r\n\r\n");

    if (body == nullptr) {
        //cout << "nobodys home" << endl;
        closeConnection(sock, ssl);
        return 1;
    }
    body += 4;

    int htmlSize = s.GetSize() - (int)(body - response);

    if (statusCode >= 200 && statusCode < 300) {
        http2++;
    }
    else if (statusCode >= 300 && statusCode < 400) {
        http3++;
    }
    else if (statusCode >= 400 && statusCode < 500) {
        http4++;
    }
    else if (statusCode >= 500 && statusCode < 600) {
        http5++;
    }
    else {
        other++;
    }

    if (statusCode == 200) {
        if (oneinput) {
            cout << "     + Parsing page... ";
        }
        //cout << "       + Parsing page... ";
        ULONGLONG parsestart = GetTickCount64();
        HTMLParserBase* parser = new HTMLParserBase;

        int nLinks = 0;

        char* linkBuffer = parser->Parse(
            body,
            htmlSize,
            input,
            (int)strlen(input),
            &nLinks);

        bool hastamulink = false;
        bool istamu = tamuhost(host);
        for (int i = 0; i < nLinks; i++) {
            string linkHost = extractHost(linkBuffer);
            if (!linkHost.empty() && tamuhost(linkHost)) {
                hastamulink = true;
            }
            linkBuffer += strlen(linkBuffer) + 1;
        }

        if (hastamulink) {
            tamu++;
            if(!istamu) {
                outsidetamu++;
			}
        }

        delete parser;
        ULONGLONG parseend = GetTickCount64() - parsestart;
        linksFound += nLinks;
        if (oneinput) {
            cout << "done in " << parseend << " ms with " << nLinks << " links" << endl;
        }
        //cout << "done in " << parseend << " ms with " << nLinks << " links" << endl;
    }

    if(oneinput) {
        cout << "       ------------------------------------------------------------------" << endl;
	}
    //cout << "------------------------------------------------------------------" << endl;

    char* headerEnd = strstr(response, "\r\n\r\n");
    if (headerEnd != nullptr) {
        size_t headerLen = headerEnd - response;
        string headers(response, headerLen);
        if(oneinput) {
            cout << headers << endl;
		}
        //cout << headers << endl;
    }
    else {
        if (oneinput) {
            cout << response << endl;
        }
        //cout << response << endl;
    }

    // close the socket (and TLS session, if any) to this server; open again for the next one
    closeConnection(sock, ssl);

    return 0;
}

queue<string> urlQueue;
mutex outputMutex;

atomic<int> completed(0);
atomic<bool> done(false);

void crawlWorker()
{
    threads++;
    while (true)
    {
        string url;

        {
            lock_guard<mutex> lock(queueMutex);

            if (pendingQueue.empty())
                return;

            url = pendingQueue.front();
            pendingQueue.pop();

            extracted++;
        }

        vector<char> buf(url.begin(), url.end());
        buf.push_back('\0');

        crawler(buf.data());
    }
    threads--;
}

void statsThread()
{
    int count = 0;
    int previous = 0;
    double pps = 0.0;
    long long previousbytes = 0;
    double mbps = 0.0;
    while (!crawlingDone)
    {
        this_thread::sleep_for(chrono::seconds(2));

        int Q;
        {
            lock_guard<mutex> lock(queueMutex);
            Q = (int)pendingQueue.size();
        }
        printf("[%3d] ", count += 2);
        printf("%4d ", threads.load());
        printf("Q %6d ", Q);
        printf("E %7d ", extracted.load());
        printf("H %6d ", hostPassed.load());
        printf("D %6d ", dnsPassed.load());
        printf("I %5d ", ipPassed.load());
        printf("R %5d ", robotsPassed.load());
        printf("C %5d ", crawled.load());
        if (linksFound.load() >= 1000) {
            printf("L %4.1fK ", linksFound.load() / 1000.0);
        }
        else {
            printf("L %4d", linksFound.load());
        }
        cout << endl;
        pps = (crawled - previous) / 2.0;
        previous = crawled;
        mbps = (downloaded - previousbytes) / 2.0 / 1024.0 / 1024.0 * 8.0;
        previousbytes = downloaded;
        cout << "       ***crawling " << pps << " pps @ " << mbps << " Mbps" << endl;
    }
}

int main(int argc, char* argv[])
{

    if (!(argc == 3 || argc == 2)) {
        cout << "Usage: " << argv[0]
            << " <num_threads> <input_file>" << endl;
        return 1;
    }

    if (argc == 2) {
        oneinput = true;
	}

    int numThreads = 0;
    if (!oneinput) {
        numThreads = atoi(argv[1]);
        if (numThreads <= 0) {
            cout << "invalid threads input" << endl;
            return 1;
        }
    }
    else {
        numThreads = 1;
    }

    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_ctx = SSL_CTX_new(TLS_client_method());
    if (g_ctx == nullptr) {
        cout << "failed to create SSL context" << endl;
        return 1;
    }

    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, nullptr);

    if (WSAStartup(wVersionRequested, &wsaData) != 0)
    {
        cout << "wsa fail" << endl;
        return 1;
    }

    if (oneinput)
    {
        auto start = chrono::steady_clock::now();

        string singleUrl = argv[1];
        vector<char> buf(singleUrl.begin(), singleUrl.end());
        buf.push_back('\0');

        int result = crawler(buf.data());

        double elapsed = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start).count() / 1000.0;

        WSACleanup();
        SSL_CTX_free(g_ctx);

        return result;
    }

    ifstream infile(argv[2]);

    if (!infile)
    {
        cout << "file open error" << endl;
        WSACleanup();
        return 1;
    }

    string url;

    while (getline(infile, url)) {
        if (!url.empty()) {
            lock_guard<mutex> lock(queueMutex);
            pendingQueue.push(url);
        }
    }

    infile.close();

    thread stats(statsThread);

    auto start = chrono::steady_clock::now();
    vector<thread> workers;

    for (int i = 0; i < numThreads; i++)
        workers.emplace_back(crawlWorker);

    for (auto& t : workers)
        t.join();

    crawlingDone = true;
    stats.join();
    WSACleanup();
    SSL_CTX_free(g_ctx);
    double elapsed = chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - start).count();
    cout << endl << endl;
    cout << "Extracted " << extracted.load() << " URLs @ " << extracted / elapsed << "/s" << endl;
    cout << "Looked up " << dnsPassed.load() << " DNS names @ " << dnsPassed / elapsed << "/s" << endl;
    cout << "Attempted " << robotsPassed.load() << " site robots @ " << robotsPassed / elapsed << "/s" << endl;
    cout << "Crawled " << crawled.load() << " pages @ " << crawled / elapsed << "/s (" << downloaded / 1000000.0 << " MB)" << endl;
    cout << "Parsed " << linksFound.load() << " links @ " << linksFound / elapsed << "/s" << endl;
    cout << "HTTP codes: 2xx = " << http2.load() << ", 3xx = " << http3.load() << ", 4xx = " << http4.load() << ", 5xx = " << http5.load() << ", other = " << other.load() << endl;
	cout << "pages with tamu links: " << tamu.load() << ", TAMU links found on outside TAMU pages: " << outsidetamu.load() << endl;


    return 0;
}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file