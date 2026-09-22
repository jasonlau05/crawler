
// Jason Lau
// CSCE 463
// Fall 2026
// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "HTMLParserBase.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <experimental/filesystem>
#include <fstream>
#include <set>
#include <unordered_set>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>

#endif PCH_H
