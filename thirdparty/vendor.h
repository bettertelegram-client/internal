#pragma once

// most basic defines to work with C.
#include <stdint.h>
#include <cassert>
#include <string>
#include <stdio.h>

// since we're format strings everywhere.
#include <format>

// works with both 32-bit and 64-bit systems.
#define _WIN defined(_WIN32) || defined(_WIN64)

#ifdef _WIN
#include <Windows.h>
#endif