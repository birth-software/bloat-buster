#define _GNU_SOURCE
#include <compiler.h>
#include <lexer.h>
#include <parser.h>
#include <stdatomic.h>
//#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __linux__
#include <unistd.h>
#include <pthread.h>

#include <liburing.h>
#define USE_IO_URING 0
#else
#define USE_IO_URING 0
#endif

#define SPALL_USE 0
#if SPALL_USE
#include <spall.h>

static SpallProfile spall_profile;
static SpallBuffer spall_buffer;
#endif
#if SPALL_USE
#define SPALL_FUNCTION_BEGIN() do { \
	spall_buffer_begin(&spall_profile, &spall_buffer, __FUNCTION__, sizeof(__FUNCTION__) - 1, __rdtsc()); \
} while(0)
#define SPALL_FUNCTION_END() do { \
	spall_buffer_end(&spall_profile, &spall_buffer, __rdtsc()); \
} while(0)
#else
#define SPALL_FUNCTION_BEGIN()
#define SPALL_FUNCTION_END()
#endif

STRUCT(CompileUnitSlice)
{
    CompileUnit* pointer;
    u64 length;
};

typedef enum CompilerBackend
{
    COMPILER_BACKEND_LLVM,
    COMPILER_BACKEND_BB,
    COMPILER_BACKEND_COUNT,
} CompilerBackend;

typedef enum LinkerBackend
{
    LINKER_BACKEND_LLD,
    LINKER_BACKEND_BB,
} LinkerBackend;

typedef enum CompilationResultId
{
    COMPILATION_RESULT_FILE_ERROR,
    COMPILATION_RESULT_LEXER_ERROR,
    COMPILATION_RESULT_PARSER_ERROR,
    COMPILATION_RESULT_SEMANTIC_ERROR,
    COMPILATION_RESULT_LLVM_IR_ERROR,
    COMPILATION_RESULT_LLVM_OPTIMIZATION_ERROR,
    COMPILATION_RESULT_LLVM_CODEGEN_ERROR,
    COMPILATION_RESULT_LINKER_ERROR,
} CompilationResultId;

STRUCT(CompilationResult)
{
    CompilationResultId id;
};

// static_assert(sizeof(CompileUnit) % CACHE_LINE_GUESS == 0);

static bool is_single_threaded = true;
static Arena* global_arena;
static CompileUnitSlice global_compile_units;
static _Atomic(u64) global_completed_compile_unit_count = 0;

static CompilationResult llvm_compile_file(CompileUnit* unit, str path)
{
    return (CompilationResult){};
}

static void llvm_compile_unit(StringSlice paths)
{
    //let arena_init_start = take_timestamp();
    let arena = arena_initialize((ArenaInitialization){});
    //let arena_init_end = take_timestamp();
    //let arena_init_ns = ns_between(arena_init_start, arena_init_end);
    //printf("Arena initialization time: %lu ns\n", arena_init_ns);

    let unit = arena_allocate(arena, CompileUnit, 1);
    memset(unit, 0, sizeof(CompileUnit));

    for (u64 i = 0; i < paths.length; i += 1)
    {
        str path = paths.pointer[i];
        llvm_compile_file(unit, path);
    }

    let index = atomic_fetch_add(&global_completed_compile_unit_count, 1);
    memcpy(&global_compile_units.pointer[index], unit, sizeof(*unit));
}

static void llvm_link_units(CompileUnitSlice compile_units)
{
}

static void report_compiler_error(str message)
{
    //printf();
}

bool compiler_is_single_threaded()
{
    return is_single_threaded;
}

static char buffer[1024 * 1024 * 1024 * 2ULL];

// static void write_random_token(u64* out_file_i, bool is_comment)
// {
//     let file_i = *out_file_i;
//     int random_n = rand();
//
//     TokenId token_id = random_n % TOKEN_COUNT;
//
//     assert(file_i < array_length(buffer));
//
//     switch (token_id)
//     {
//         break; case TOKEN_ID_IDENTIFIER:
//         {
//             int identifier_character_count = random_n % 64;
//             char* identifier_start = &buffer[file_i];
//
//             for (int i = 0; i < identifier_character_count; i += 1)
//             {
//                 int id_ch_rand = rand();
//                 int choice = id_ch_rand % (3 - (i == 0));
//
//                 char c;
//
//                 switch (choice)
//                 {
//                     break; case 0:
//                     {
//                         c = 'a' + (id_ch_rand % ('z' - 'a'));
//                     }
//                     break; case 1:
//                     {
//                         c = 'A' + (id_ch_rand % ('Z' - 'A'));
//                     }
//                     break; case 2:
//                     {
//                         char first_ch = i != 0 ? *identifier_start : 0;
//                         c = ((first_ch == 's') | (first_ch == 'u') | (first_ch == 'f')) ? first_ch : ('0' + (id_ch_rand % ('9' - '0')));
//                     }
//                 }
//
//                 buffer[file_i] = c;
//                 file_i += 1;
//             }
//         }
//         break; case TOKEN_ID_INTEGER:
//         {
//             int integer_literal_character_count = random_n % 32;
//
//             for (int i = 0; i < integer_literal_character_count; i += 1)
//             {
//                 int id_ch_rand = rand();
//                 char c = '0' + (id_ch_rand % ('9' - '0'));
//
//                 buffer[file_i] = c;
//                 file_i += 1;
//             }
//         }
//         break; case TOKEN_ID_FLOAT:
//             break; case TOKEN_ID_FLOAT_STRING_LITERAL:
//             {
//                 int integer_literal_character_count = random_n % 16;
//
//                 for (int i = 0; i < integer_literal_character_count; i += 1)
//                 {
//                     int id_ch_rand = rand();
//                     char c = '0' + (id_ch_rand % ('9' - '0'));
//
//                     buffer[file_i] = c;
//                     file_i += 1;
//                 }
//
//                 buffer[file_i] = '.';
//                 file_i += 1;
//
//                 for (int i = 0; i < integer_literal_character_count; i += 1)
//                 {
//                     int id_ch_rand = rand();
//                     char c = '0' + (id_ch_rand % ('9' - '0'));
//
//                     buffer[file_i] = c;
//                     file_i += 1;
//                 }
//             }
//         break; case TOKEN_ID_STRING_LITERAL:
//         {
//             assert(buffer[file_i - 1] != '\\');
//             buffer[file_i] = '"';
//             file_i += 1;
//
//             int identifier_character_count = random_n % 64;
//
//             for (int i = 0; i < identifier_character_count; i += 1)
//             {
//                 int id_ch_rand = rand();
//                 int choice = id_ch_rand % 3;
//
//                 char c;
//
//                 switch (choice)
//                 {
//                     break; case 0:
//                     {
//                         c = 'a' + (id_ch_rand % ('z' - 'a'));
//                     }
//                     break; case 1:
//                     {
//                         c = 'A' + (id_ch_rand % ('Z' - 'A'));
//                     }
//                     break; case 2:
//                     {
//                         c = '0' + (id_ch_rand % ('9' - '0'));
//                     }
//                 }
//
//                 buffer[file_i] = c;
//                 file_i += 1;
//             }
//
//             buffer[file_i] = '"';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_CHARACTER_LITERAL:
//         {
//             buffer[file_i] = '\'';
//             file_i += 1;
//
//             int id_ch_rand = rand();
//             int choice = id_ch_rand % 3;
//
//             char c;
//
//             switch (choice)
//             {
//                 break; case 0:
//                 {
//                     c = 'a' + (id_ch_rand % ('z' - 'a'));
//                 }
//                 break; case 1:
//                 {
//                     c = 'A' + (id_ch_rand % ('Z' - 'A'));
//                 }
//                 break; case 2:
//                 {
//                     c = '0' + (id_ch_rand % ('9' - '0'));
//                 }
//             }
//
//             buffer[file_i] = c;
//             file_i += 1;
//
//             buffer[file_i] = '\'';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_INTEGER:
//         {
//             int r = rand();
//
//             bool is_signed = r % 2;
//             char first_ch = is_signed ? 's' : 'u';
//
//             buffer[file_i] = first_ch;
//             file_i += 1;
//
//             int bit_count = (r % 64) + 1;
//
//             if (bit_count >= 10)
//             {
//                 buffer[file_i] = '0' + (bit_count / 10);
//                 file_i += 1;
//
//                 buffer[file_i] = '0' + (bit_count % 10);
//                 file_i += 1;
//             }
//             else
//             {
//                 char c = bit_count + '0';
//
//                 buffer[file_i] = c;
//                 file_i += 1;
//             }
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_FLOAT:
//         {
//             int r = rand();
//
//             buffer[file_i] = 'f';
//             file_i += 1;
//
//             int choice = r % 3;
//
//             switch (choice)
//             {
//                 break; case 0:
//                 {
//                     buffer[file_i] = '3';
//                     file_i += 1;
//                     buffer[file_i] = '2';
//                     file_i += 1;
//                 }
//                 break; case 1:
//                 {
//                     buffer[file_i] = '6';
//                     file_i += 1;
//                     buffer[file_i] = '4';
//                     file_i += 1;
//                 }
//                 break; case 2:
//                 {
//                     buffer[file_i] = '1';
//                     file_i += 1;
//                     buffer[file_i] = '2';
//                     file_i += 1;
//                     buffer[file_i] = '8';
//                     file_i += 1;
//                 }
//             }
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE:
//         {
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 'y';
//             file_i += 1;
//             buffer[file_i] = 'p';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_VOID:
//         {
//             buffer[file_i] = 'v';
//             file_i += 1;
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 'd';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_NORETURN:
//         {
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_ENUM:
//         {
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'm';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_STRUCT:
//         {
//             buffer[file_i] = 's';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'c';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_BITS:
//         {
//             buffer[file_i] = 'b';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 's';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_UNION:
//         {
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_FN:
//         {
//             buffer[file_i] = 'f';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_ALIAS:
//         {
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'l';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 's';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_VECTOR:
//         {
//             buffer[file_i] = 'v';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'c';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_ENUM_ARRAY:
//         {
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'm';
//             file_i += 1;
//             buffer[file_i] = '_';
//             file_i += 1;
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'y';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_TYPE_OPAQUE:
//         {
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'p';
//             file_i += 1;
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'q';
//             file_i += 1;
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_UNDERSCORE:
//         {
//             buffer[file_i] = '_';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_RETURN:
//         {
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_IF:
//         {
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 'f';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_WHEN:
//         {
//             buffer[file_i] = 'w';
//             file_i += 1;
//             buffer[file_i] = 'h';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_FOR:
//         {
//             buffer[file_i] = 'f';
//             file_i += 1;
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_WHILE:
//         {
//             buffer[file_i] = 'w';
//             file_i += 1;
//             buffer[file_i] = 'h';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 'l';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_SWITCH:
//         {
//             buffer[file_i] = 's';
//             file_i += 1;
//             buffer[file_i] = 'w';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 'c';
//             file_i += 1;
//             buffer[file_i] = 'h';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_BREAK:
//         {
//             buffer[file_i] = 'b';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'k';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_CONTINUE:
//         {
//             buffer[file_i] = 'c';
//             file_i += 1;
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 't';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_UNREACHABLE:
//         {
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'c';
//             file_i += 1;
//             buffer[file_i] = 'h';
//             file_i += 1;
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'b';
//             file_i += 1;
//             buffer[file_i] = 'l';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_STATEMENT_ELSE:
//         {
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'l';
//             file_i += 1;
//             buffer[file_i] = 's';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_VALUE_UNDEFINED:
//         {
//             buffer[file_i] = 'u';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'd';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'f';
//             file_i += 1;
//             buffer[file_i] = 'i';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'd';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_VALUE_ZERO:
//         {
//             buffer[file_i] = 'z';
//             file_i += 1;
//             buffer[file_i] = 'e';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = 'o';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_OPERATOR_AND:
//         {
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'd';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_OPERATOR_OR:
//         {
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_OPERATOR_AND_SHORTCIRCUIT:
//         {
//             buffer[file_i] = 'a';
//             file_i += 1;
//             buffer[file_i] = 'n';
//             file_i += 1;
//             buffer[file_i] = 'd';
//             file_i += 1;
//             buffer[file_i] = '?';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_KEYWORD_OPERATOR_OR_SHORTCIRCUIT:
//         {
//             buffer[file_i] = 'o';
//             file_i += 1;
//             buffer[file_i] = 'r';
//             file_i += 1;
//             buffer[file_i] = '?';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_ASSIGN:
//         {
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COMPARE_EQUAL:
//         {
//             buffer[file_i] = '=';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_SWITCH_CASE:
//         {
//             buffer[file_i] = '=';
//             file_i += 1;
//             buffer[file_i] = '>';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_EXCLAMATION_DOWN:
//         {
//             buffer[file_i] = '!';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COMPARE_NOT_EQUAL:
//         {
//             buffer[file_i] = '!';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COMPARE_LESS:
//         {
//             buffer[file_i] = '<';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COMPARE_LESS_EQUAL:
//         {
//             buffer[file_i] = '<';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_SHIFT_LEFT:
//         {
//             buffer[file_i] = '<';
//             file_i += 1;
//             buffer[file_i] = '<';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_SHIFT_LEFT_ASSIGN:
//         {
//             buffer[file_i] = '<';
//             file_i += 1;
//             buffer[file_i] = '<';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COMPARE_GREATER:
//         {
//             buffer[file_i] = '>';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COMPARE_GREATER_EQUAL:
//         {
//             buffer[file_i] = '>';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_SHIFT_RIGHT:
//         {
//             buffer[file_i] = '>';
//             file_i += 1;
//             buffer[file_i] = '>';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_SHIFT_RIGHT_ASSIGN:
//         {
//             buffer[file_i] = '>';
//             file_i += 1;
//             buffer[file_i] = '>';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_PLUS:
//         {
//             buffer[file_i] = '+';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_ADD_ASSIGN:
//         {
//             buffer[file_i] = '+';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_DASH:
//         {
//             buffer[file_i] = '-';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_SUB_ASSIGN:
//         {
//             buffer[file_i] = '-';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_ASTERISK:
//         {
//             buffer[file_i] = '*';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_MUL_ASSIGN:
//         {
//             buffer[file_i] = '*';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_FORWARD_SLASH:
//         {
//             buffer[file_i] = '/';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_DIV_ASSIGN:
//         {
//             buffer[file_i] = '/';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_PERCENTAGE:
//         {
//             buffer[file_i] = '%';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_REM_ASSIGN:
//         {
//             buffer[file_i] = '%';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_AMPERSAND:
//         {
//             buffer[file_i] = '&';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_BITWISE_AND_ASSIGN:
//         {
//             buffer[file_i] = '&';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_BAR:
//         {
//             buffer[file_i] = '|';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_BITWISE_OR_ASSIGN:
//         {
//             buffer[file_i] = '|';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_CARET:
//         {
//             buffer[file_i] = '^';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_BITWISE_XOR_ASSIGN:
//         {
//             buffer[file_i] = '^';
//             file_i += 1;
//             buffer[file_i] = '=';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_DOT:
//         {
//             buffer[file_i] = '.';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_POINTER_DEREFERENCE:
//         {
//             buffer[file_i] = '.';
//             file_i += 1;
//             buffer[file_i] = '&';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_OPTIONAL_DEREFERENCE:
//         {
//             buffer[file_i] = '.';
//             file_i += 1;
//             buffer[file_i] = '?';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_DOUBLE_DOT:
//         {
//             buffer[file_i] = '.';
//             file_i += 1;
//             buffer[file_i] = '.';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_TRIPLE_DOT:
//         {
//             buffer[file_i] = '.';
//             file_i += 1;
//             buffer[file_i] = '.';
//             file_i += 1;
//             buffer[file_i] = '.';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_LEFT_PARENTHESIS:
//         {
//             buffer[file_i] = '(';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_RIGHT_PARENTHESIS:
//         {
//             buffer[file_i] = ')';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_LEFT_BRACE:
//         {
//             buffer[file_i] = '{';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_RIGHT_BRACE:
//         {
//             buffer[file_i] = '}';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_LEFT_BRACKET:
//         {
//             buffer[file_i] = '[';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_RIGHT_BRACKET:
//         {
//             buffer[file_i] = ']';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COMMA:
//         {
//             buffer[file_i] = ',';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_SEMICOLON:
//         {
//             buffer[file_i] = ';';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_COLON:
//         {
//             buffer[file_i] = ':';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_QUESTION:
//         {
//             buffer[file_i] = '?';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_AT:
//         {
//             buffer[file_i] = '@';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_BACKTICK:
//         {
//             buffer[file_i] = '`';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_BACKSLASH:
//         {
//             buffer[file_i] = '\\';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_HASH:
//         {
//             buffer[file_i] = '#';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_DOLLAR:
//         {
//             buffer[file_i] = '$';
//             file_i += 1;
//         }
//         break; case TOKEN_ID_TILDE:
//         {
//             buffer[file_i] = '~';
//             file_i += 1;
//         }
//         break; case TOKEN_COUNT: UNREACHABLE();
//         break; default: {};
//     }
//
//     buffer[file_i] = ' ';
//     file_i += 1;
//
//     if (random_n % 8 == 0)
//     {
//         buffer[file_i] = '\n';
//         file_i += 1;
//     }
//
//     *out_file_i = file_i;
//
//     if (!is_comment && random_n % 100 == 0)
//     {
//         buffer[file_i] = '/';
//         file_i += 1;
//         buffer[file_i] = '/';
//         file_i += 1;
//         *out_file_i = file_i;
//
//         let token_count = random_n % 64;
//
//         for (u64 i = 0; i < token_count; i += 1)
//         {
//             write_random_token(out_file_i, 1);
//         }
//
//         file_i = *out_file_i;
//
//         buffer[file_i] = '\n';
//         file_i += 1;
//
//         *out_file_i = file_i;
//     }
//
//     *out_file_i = file_i;
// }

// static void write_random_file(str path)
// {
//     u64 file_i = 0;
//
//     for (u64 i = 0; i < 50000000; i += 1)
//     {
//         write_random_token(&file_i, 0);
//     }
//
//     let fd = os_file_open(path, (OpenFlags) {
//         .create = 1,
//         .truncate = 1,
//         .write = 1,
//     }, (OpenPermissions) {
//         .read = 1,
//         .write = 1,
//     });
//
//     os_file_write(fd, (str) { buffer, file_i });
//
//     os_file_close(fd);
// }

static str file_paths[] = {
    S("build/file0"),
    S("build/file1"),
    S("build/file2"),
    S("build/file3"),
    S("build/file4"),
    S("build/file5"),
    S("build/file6"),
    S("build/file7"),
    S("build/file8"),
    S("build/file9"),
    S("build/file10"),
    S("build/file11"),
    S("build/file12"),
    S("build/file13"),
    S("build/file14"),
    S("build/file15"),
    S("build/file16"),
    S("build/file17"),
    S("build/file18"),
    S("build/file19"),
    S("build/file20"),
    S("build/file21"),
    S("build/file22"),
    S("build/file23"),
    S("build/file24"),
    S("build/file25"),
    S("build/file26"),
    S("build/file27"),
    S("build/file28"),
    S("build/file29"),
    S("build/file30"),
    S("build/file31"),
    S("build/file32"),
    S("build/file33"),
    S("build/file34"),
    S("build/file35"),
    S("build/file36"),
    S("build/file37"),
    S("build/file38"),
    S("build/file39"),
    S("build/file40"),
    S("build/file41"),
    S("build/file42"),
    S("build/file43"),
    S("build/file44"),
    S("build/file45"),
    S("build/file46"),
    S("build/file47"),
    S("build/file48"),
    S("build/file49"),
    S("build/file50"),
    S("build/file51"),
    S("build/file52"),
    S("build/file53"),
    S("build/file54"),
    S("build/file55"),
    S("build/file56"),
    S("build/file57"),
    S("build/file58"),
    S("build/file59"),
    S("build/file60"),
    S("build/file61"),
    S("build/file62"),
    S("build/file63"),
    S("build/file64"),
    S("build/file65"),
    S("build/file66"),
    S("build/file67"),
    S("build/file68"),
    S("build/file69"),
    S("build/file70"),
    S("build/file71"),
    S("build/file72"),
    S("build/file73"),
    S("build/file74"),
    S("build/file75"),
    S("build/file76"),
    S("build/file77"),
    S("build/file78"),
    S("build/file79"),
    S("build/file80"),
    S("build/file81"),
    S("build/file82"),
    S("build/file83"),
    S("build/file84"),
    S("build/file85"),
    S("build/file86"),
    S("build/file87"),
    S("build/file88"),
    S("build/file89"),
    S("build/file90"),
    S("build/file91"),
    S("build/file92"),
    S("build/file93"),
    S("build/file94"),
    S("build/file95"),
    S("build/file96"),
    S("build/file97"),
    S("build/file98"),
    S("build/file99"),
};

static int fds[array_length(file_paths)];
#ifdef __linux__
static struct statx statxs[array_length(file_paths)];
#endif
static str file_contents[array_length(file_paths)];

TokenList io_uring_tl[array_length(file_paths)];
TokenList sync_tl[array_length(file_paths)];

typedef enum IoUringTask
{
    IO_URING_TASK_OPEN,
    IO_URING_TASK_STAT,
    IO_URING_TASK_READ,
    IO_URING_TASK_CLOSE,
} IoUringTask;

#ifdef __linux__
static u64 io_uring_task(Arena* file_arena, Arena* else_arena, struct io_uring* restrict ring, StringSlice file_paths, int* restrict fd_array, struct statx* restrict statx_array, str* restrict file_array, TokenList* restrict list_array)
{
    SPALL_FUNCTION_BEGIN();
    let file_count = file_paths.length;
    if (file_count > UINT32_MAX)
    {
        fail();
    }

    u64 pending = file_count;
    for (u64 i = 0; i < pending; i += 1)
    {
        struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
        io_uring_prep_openat(sqe, AT_FDCWD, file_paths.pointer[i].pointer, O_RDONLY, 0);
        sqe->user_data = ((u64)(IO_URING_TASK_OPEN) << 32) | i;
    }

    int ret = io_uring_submit(ring);
    if (ret < 0)
    {
        fail();
    }

    struct io_uring_cqe* open_cqes;

    for (u64 cqe_i = 0; cqe_i < file_count; cqe_i += 1)
    {
        struct io_uring_cqe* cqe;
        ret = io_uring_wait_cqe(ring, &cqe);
        if (ret < 0)
        {
            fail();
        }

        let user_data = cqe->user_data;
        let result = cqe->res;
        let i = (u32)user_data;
        let task = (IoUringTask)(user_data >> 32);

        assert(task == IO_URING_TASK_OPEN);
        io_uring_cqe_seen(ring, cqe);

        let fd = result;
        if (fd < 0)
        {
            fail();
        }
        fd_array[i] = fd;

        struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
        int flags = AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_DONT_SYNC;
        int mask = STATX_SIZE;
        io_uring_prep_statx(sqe, fd, "", flags, mask, &statx_array[i]);
        sqe->user_data = ((u64)(IO_URING_TASK_STAT) << 32) | i;
    }

    ret = io_uring_submit(ring);
    if (ret < 0)
    {
        fail();
    }

    pending = file_count;

    while (pending)
    {
        struct io_uring_cqe* cqe;
        let ret = io_uring_wait_cqe(ring, &cqe);

        if (ret < 0)
        {
            fail();
        }

        let user_data = cqe->user_data;
        let result = cqe->res;
        let i = (u32)user_data;
        let task = (IoUringTask)(user_data >> 32);

        io_uring_cqe_seen(ring, cqe);

        switch (task)
        {
            break; case IO_URING_TASK_OPEN:
            {
                UNREACHABLE();
            }
            break; case IO_URING_TASK_STAT:
            {
                pending -= 1;
                let fd = fd_array[i];
                if (result != 0)
                {
                    let er = strerror(result);
                    printf("Error in stat task: %s\n", er);
                    fflush(stdout);
                    fail();
                }
                let statx_struct = &statx_array[i];
                let file_size = statx_struct->stx_size;
                let file_pointer = arena_allocate_bytes(file_arena, file_size, 1);
                let file = (str) { file_pointer, file_size };
                file_array[i] = file;

                u64 read_byte_count = 0;

                while (read_byte_count != file.length)
                {
                    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
                    u32 to_be_read = file.length > 0x7ffff000 ? 0x7ffff000 : (u32)file.length;
                    sqe->flags |= IOSQE_IO_LINK;
                    u64 user_data = ((u64)(IO_URING_TASK_READ) << 32) | i;
                    sqe->user_data = user_data;
                    io_uring_prep_read(sqe, fd, file.pointer, to_be_read, read_byte_count);
                    read_byte_count += to_be_read;
                }

                struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
                io_uring_prep_close(sqe, fd);
                u64 user_data = ((u64)(IO_URING_TASK_CLOSE) << 32) | i;
                sqe->user_data = user_data;

                ret = io_uring_submit(ring);
                if (ret < 0)
                {
                    fail();
                }
            }
            break; case IO_URING_TASK_READ:
            {
            }
            break; case IO_URING_TASK_CLOSE:
            {
                printf("file first: %c\n", file_array[i].pointer[0]);
            }
        }
    }

    // for (u64 i = 0; i < file_count; i += 1)
    // {
    //     LexerError error = {};
    //     let token_list = lex(file_arena, else_arena, file_array[i], &error);
    //     if (error.id != LEXER_ERROR_ID_NONE)
    //     {
    //         fail();
    //     }
    //     list_array[i] = token_list;
    // }

    SPALL_FUNCTION_END();
    return file_count;
}
#endif

STRUCT(Thread)
{
#ifdef __linux__
    pthread_t handle;
#elif _WIN32
    void* handle;
#endif
    StringSlice work;
    void* return_value;
    u8 padding[64 - 4 * sizeof(u64)];
};

static_assert(sizeof(Thread) % 64 == 0);

#define THREAD_COUNT 5
static Thread threads[5];
static u32 thread_count;
static u32 per_thread_work;

static CompileUnit* compile_unit_create()
{
    let arena = arena_initialize((ArenaInitialization) {
        .count = UNIT_ARENA_COUNT,
    });

    let compile_unit = arena_allocate(arena, CompileUnit, 1);
    *compile_unit = (CompileUnit) {};

    return compile_unit;
}

static StringReference string_reference_from_string(CompileUnit* restrict unit, str s)
{
    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena->position;
    assert((arena_bottom < s.pointer) & (arena_top > s.pointer));
    let string_top = s.pointer + s.length;
    assert(string_top <= arena_top);
    let length_pointer = (u32*)s.pointer - 1;
    let length = *length_pointer;
    assert(s.length == length);

    let diff = (char*)length_pointer - arena_top;
    assert(diff < UINT32_MAX);
    return (StringReference) {
        .v = diff + 1,
    };
}

static StringReference allocate_string_if_needed(CompileUnit* restrict unit, str s)
{
    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena->position;

    if ((s.pointer > arena_bottom) & (s.pointer < arena_top))
    {
        // let string_reference = string_reference_from_string(unit, s);
        trap();
    }
    else
    {
        assert(s.length <= UINT32_MAX);
        let string = (char* restrict) arena_allocate_bytes(arena, s.length + sizeof(u32) + 1, alignof(u32));
        *(u32*)string = (u32)s.length;
        memcpy(string + sizeof(u32), s.pointer, s.length);
        *(string + sizeof(u32) + s.length) = 0;
        let big_offset = string - arena_byte_pointer;
        assert(big_offset + 1 < UINT32_MAX);
        let offset = (u32)big_offset;
        let reference = (StringReference) {
            .v = offset + 1,
        };
        return reference;
    }
}

static void crunch_file(CompileUnit* restrict unit, str path)
{
    let string_arena = unit_arena(unit, UNIT_ARENA_STRING);
    str content = file_read(string_arena, path, (FileReadOptions){
        .start_padding = sizeof(u32),
        .start_alignment = alignof(u32),
    });
    assert(content.length < UINT32_MAX);
    *((u32*)content.pointer - 1) = content.length;
    let content_reference = string_reference_from_string(unit, content);

    let path_reference = allocate_string_if_needed(unit, path);

    let global_scope = scope_reference_from_pointer(unit, &unit->scope);

    let arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
    let file = arena_allocate(arena, File, 1);
    *file = (File) {
        .content = content_reference,
        .path = path_reference,
        .scope = {
            .parent = global_scope,
            .id = SCOPE_ID_FILE,
        },
    };
    trap();
    // *file = (File) {
    //     .content = content,
    //     .path = path,
    //     .scope = {
    //         .parent = global_scope,
    //         .id = SCOPE_ID_FILE,
    //     },
    //     .next = 0,
    // };
    // let scope = scope_offset_from_pointer(unit, &file->scope);
    // let tl = lex(thread_arena, else_arena, content.pointer, content.length);
}

void* thread_worker(void* arg)
{
    let thread_index = (u64)arg;
    u64 result_code = 0;
    Thread* thread = &threads[thread_index];
    let thread_file_count = thread->work.length;
    Arena* thread_arena = arena_initialize((ArenaInitialization){
        .reserved_size = GB(32),
        .initial_size = GB(32),
    });
    Arena* else_arena = arena_initialize((ArenaInitialization){
        .reserved_size = GB(12),
        .initial_size = GB(12),
    });
    str path = 
#if 0
            S("build/file0");
#else
            S("tests/tests.bbb");
#endif

    let unit = compile_unit_create();

    crunch_file(unit, path);

    // if (tl.length)
    // {
    //     let last_token = tl.pointer[tl.length - 1];
    //     if (last_token.id != TOKEN_ID_EOF)
    //     {
    //         trap();
    //     }
    //
    //     parse_file(unit, path, content, tl);
    // }

    trap();
#if USE_IO_URING
    struct io_uring ring;
    let ret = io_uring_queue_init(thread_file_count * 2, &ring, 0);
    if (ret == 0)
    {
        fail();
    }
    else
    {
        let er = strerror(-ret);
        printf("io_uring_queue_init failed: %s\n", er);
        result_code = 1;
    }
#endif

    return (void*)result_code;
}

bool compiler_main(int argc, const char* argv[], char** envp)
{
    os_init();
    bool result = 1;
    StringSlice file_path_slice = { file_paths, array_length(file_paths) };
    bool is_single_threaded = 1;
    u64 thread_file_count = is_single_threaded ? file_path_slice.length : file_path_slice.length / 5;
    thread_count = is_single_threaded ? 1 : THREAD_COUNT;

    if (is_single_threaded)
    {
        Thread* restrict thread = &threads[0];
        thread->work = file_path_slice;
#if 0
        write_random_file(file_paths[0]);
#else
        void* thread_result = thread_worker((void*)0);
        result = (u64)thread_result == 0;
#endif
    }
    else
    {
        for (u64 i = 0; i < thread_count; i += 1)
        {
            Thread* restrict thread = &threads[i];
            thread->work = (StringSlice){ file_path_slice.pointer + thread_file_count * i, thread_file_count };
#ifdef __linux__
            let result = pthread_create(&thread->handle, 0, &thread_worker, (void*)i);
            if (result != 0)
            {
                fail();
            }
#else
#endif
        }

        for (u64 i = 0; i < thread_count; i += 1)
        {
            Thread* restrict thread = &threads[i];
#ifdef __linux__
            let result = pthread_join(thread->handle, &thread->return_value);
            if (result != 0)
            {
                fail();
            }
#else
#endif
        }
    }

//     assert(sr == 0);
//
//     Arena* random_arena = arena_initialize((ArenaInitialization){
//         .reserved_size = GB(8) - sizeof(Arena),
//         .initial_size = GB(8) - sizeof(Arena),
//     });
//
// #if SPALL_USE
//     if (!spall_init_file("build/profile.spall", 1, &spall_profile))
//     {
//         return 0;
//     }
// #endif
//
// #if 0
//     for (u64 i = 0; i < file_path_slice.length; i += 1)
//     {
//         write_random_file(file_path_slice.pointer[i]);
//     }
// #else
//
//     // TODO: parse command-line arguments
//     // SliceOfStringSlice paths_array = { &string_array_to_slice(files), 1 };
//     // u64 compile_unit_count = paths_array.length;
//     // global_compile_units = (CompileUnitSlice){ arena_allocate(global_arena, CompileUnit, compile_unit_count), compile_unit_count };
//     struct io_uring ring;
//     let queue_init = io_uring_queue_init(file_path_slice.length * 2, &ring, 0);
//     if (queue_init < 0)
//     {
//         let er = strerror(-queue_init);
//         printf("io_uring_queue_init failed: %s\n", er);
//         return false;
//     }
//
//     int iteration_times = 10;
//
//     u64 io_uring_max_ns = 0;
//     u64 io_uring_min_ns = UINT64_MAX;
//     u64 io_uring_accumulator = 0;
//     
// #if SPALL_USE
//     let spall_buffer_size = MB(100);
//     let spall_buffer_pointer = arena_allocate_bytes(global_arena, spall_buffer_size, 1);
//     spall_buffer = (SpallBuffer) {
//         .pid = 0,
//         .tid = 0,
//         .length = spall_buffer_size,
//         .data = spall_buffer_pointer,
//     };
//     spall_buffer_init(&spall_profile, &spall_buffer);
// #endif
//
//     let previous_timestamp = take_timestamp();
//
//     for (int i = 0; i < iteration_times; i += 1)
//     {
//         let start_timestamp = previous_timestamp;
//
//         arena_reset_to_start(global_arena);
//         arena_reset_to_start(random_arena);
//
//         let completed_file_count = io_uring_task(global_arena, random_arena, &ring, file_path_slice, fds, statxs, file_contents, io_uring_tl);
//         if (completed_file_count != file_path_slice.length)
//         {
//             fail();
//         }
//
//         let end_timestamp = take_timestamp();
//         let iteration_ns = ns_between(start_timestamp, end_timestamp);
//
//         io_uring_max_ns = iteration_ns > io_uring_max_ns ? iteration_ns : io_uring_max_ns;
//         io_uring_min_ns = iteration_ns < io_uring_min_ns ? iteration_ns : io_uring_min_ns;
//         io_uring_accumulator += iteration_ns;
//
//         previous_timestamp = end_timestamp;
//     }

// #if SPALL_USE
//     spall_buffer_quit(&spall_profile, &spall_buffer);
// #endif
//
//     let io_uring_average = (f64)io_uring_accumulator / iteration_times;
//     printf("io_uring:\n\taverage: %f ns\n\tmin: %lu ns\n\tmax: %lu ns\n", io_uring_average, io_uring_min_ns, io_uring_max_ns);
// #endif

    //u64 sync_max_ns = 0;
    //u64 sync_min_ns = UINT64_MAX;
    //u64 sync_accumulator = 0;

    //for (int i = 0; i < iteration_times; i += 1)
    //{
    //}

    // if (is_single_threaded)
    // {
    //     llvm_compile_unit(string_array_to_slice(paths));
    // }
    // else
    // {
    //     fail();
    // }
    
#if SPALL_USE
    spall_quit(&spall_profile);
#endif

    return result;
}
