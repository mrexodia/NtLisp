#pragma once

// Assuming the platform specific header is included already.
#define NTLISP_RUN CTL_CODE( 0x13, 0x37, METHOD_BUFFERED, FILE_ANY_ACCESS )

// Shared structures.
//
struct ntlisp_result
{
    char* errors;
    char* outputs;
};