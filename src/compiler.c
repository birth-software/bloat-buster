#define _GNU_SOURCE
#include <compiler.h>
#include <lexer.h>
#include <parser.h>
#include <analysis.h>
#include <stdatomic.h>
#include <stdio.h>
#ifdef __linux__
#include <unistd.h>
#include <pthread.h>

#define USE_IO_URING 0
#else
#define USE_IO_URING 0
#endif

#if USE_IO_URING
#include <liburing.h>
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

static u64 classic_integer_type_count = 64 * 2;
static u64 big_integer_type_count = (
        1 +  // 128
        1 +  // 256
        1    // 512
        ) * 2;
static u64 void_noreturn_type_count = 2;

static CompileUnit* compile_unit_create()
{
    let arena = arena_initialize((ArenaInitialization) {
        .count = UNIT_ARENA_COUNT,
    });

    let unit = arena_allocate(arena, CompileUnit, 1);
    *unit = (CompileUnit) {};
    let global_scope = unit->scope;
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    assert(type_arena->position == sizeof(Arena));

    let base_type_count = classic_integer_type_count + big_integer_type_count + void_noreturn_type_count;
    let base_type_allocation = arena_allocate(type_arena, Type, base_type_count);

    let type = base_type_allocation;

    for (u8 is_signed = 0; is_signed < 2; is_signed += 1)
    {
        for (u64 bit_count = 1; bit_count <= 64; bit_count += 1)
        {
            char first_digit = bit_count < 10 ? bit_count % 10 + '0' : bit_count / 10 + '0';
            char second_digit = bit_count > 9 ? bit_count % 10 + '0' : 0;
            char buffer[] = { is_signed ? 's' : 'u', first_digit, second_digit };
            u64 name_length = 2 + (bit_count > 9);

            let name = allocate_string(unit, (str){ buffer, name_length });
            
            *type = (Type){
                .integer = {
                    .bit_count = bit_count,
                    .is_signed = is_signed,
                },
                .name = name,
                .scope = global_scope,
                .id = TYPE_ID_INTEGER,
                .analyzed = 1,
            };
            type += 1;
        }
    }

    const static str names[] = { S("u128"), S("s128"), S("u256"), S("s256"), S("u512"), S("s512") };
    assert(array_length(names) == big_integer_type_count);
    for (u64 i = 0; i < (big_integer_type_count / 2); i += 1)
    {
        for (u8 is_signed = 0; is_signed < 2; is_signed += 1)
        {
            let bit_count = 128ULL << i;
            let name = allocate_string(unit, names[i * 2 + is_signed]);
            *type = (Type) {
                .integer = {
                    .bit_count = bit_count,
                    .is_signed = is_signed,
                },
                .name = name,
                .scope = global_scope,
                .id = TYPE_ID_INTEGER,
                .analyzed = 1,
            };
        }
    }

    let f16_type = type;
    type += 1;

    let bf16_type = type;
    type += 1;

    let f32_type = type;
    type += 1;

    let f64_type = type;
    type += 1;

    let f128_type = type;
    type += 1;

    let void_type = type;
    type += 1;

    let noreturn_type = type;
    type += 1;

    *f16_type = (Type) {
        .fp = TYPE_FLOAT_F16,
        .name = allocate_string(unit, S("f16")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
    };

    *bf16_type = (Type) {
        .fp = TYPE_FLOAT_BF16,
        .name = allocate_string(unit, S("bf16")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
    };

    *f32_type = (Type) {
        .fp = TYPE_FLOAT_F32,
        .name = allocate_string(unit, S("f32")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
    };

    *f64_type = (Type) {
        .fp = TYPE_FLOAT_F64,
        .name = allocate_string(unit, S("f64")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
    };

    *f128_type = (Type) {
        .fp = TYPE_FLOAT_F128,
        .name = allocate_string(unit, S("f128")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
    };

    *void_type = (Type) {
        .name = allocate_string(unit, S("void")),
        .scope = global_scope,
        .id = TYPE_ID_VOID,
        .analyzed = 1,
    };

    *noreturn_type = (Type) {
        .name = allocate_string(unit, S("noreturn")),
        .scope = global_scope,
        .id = TYPE_ID_NORETURN,
        .analyzed = 1,
    };

    let void_value = arena_allocate(unit_arena(unit, UNIT_ARENA_VALUE), Value, 1);
    *void_value = (Value) {
        .type = get_void_type(unit),
        .id = VALUE_ID_DISCARD,
    };

    return unit;
}

TypeReference get_void_type(CompileUnit* restrict unit)
{
    let void_offset = classic_integer_type_count + big_integer_type_count;
    let void_type = type_reference_from_index(unit, void_offset);
    return void_type;
}

TypeReference get_noreturn_type(CompileUnit* restrict unit)
{
    let void_type = get_void_type(unit);
    void_type.v += 1;
    return void_type;
}

TypeReference get_integer_type(CompileUnit* restrict unit, u64 bit_count, bool is_signed)
{
    assert(bit_count != 0);
    assert(bit_count <= 64 || bit_count == 128 || bit_count == 256 || bit_count == 512);
    let type_index = bit_count > 64 ? (1ULL << __builtin_ctzg(bit_count - 128)) * 2 + is_signed : is_signed * 64 + (bit_count - 1);
    return type_reference_from_index(unit, type_index);
}

TypeReference get_pointer_type(CompileUnit* restrict unit, TypeReference element_type_reference)
{
    assert(unit->phase >= COMPILE_PHASE_ANALYSIS);

    Type* element_type = type_pointer_from_reference(unit, element_type_reference);
    let last_pointer_type = unit->first_pointer_type;

    while (is_ref_valid(last_pointer_type))
    {
        let lpt = type_pointer_from_reference(unit, last_pointer_type);
        assert(lpt->id == TYPE_ID_POINTER);
        if (ref_eq(lpt->pointer.element_type, element_type_reference))
        {
            return last_pointer_type;
        }

        let next = lpt->pointer.next;
        if (!is_ref_valid(next))
        {
            break;
        }

        last_pointer_type = next;
    }

    StringReference name = {};
    if (is_ref_valid(element_type->name))
    {
        str name_parts[] = {
            S("&"),
            string_from_reference(unit, element_type->name),
        };
        name = allocate_and_join_string(unit, string_array_to_slice(name_parts));
    }

    let pointer = new_type(unit);
    *pointer = (Type) {
        .pointer = {
            .element_type = element_type_reference,
        },
        .name = name,
        .scope = element_type->scope,
        .id = TYPE_ID_POINTER,
    };

    let result =  type_reference_from_pointer(unit, pointer);

    if (is_ref_valid(last_pointer_type))
    {
        assert(is_ref_valid(unit->first_pointer_type));
        let lpt = type_pointer_from_reference(unit, last_pointer_type);
        lpt->pointer.next = result;
    }
    else
    {
        assert(!is_ref_valid(unit->first_pointer_type));
        unit->first_pointer_type = result;
    }

    return result;
}

StringReference allocate_string(CompileUnit* restrict unit, str s)
{
    str slices[] = { s };
    return allocate_and_join_string(unit, string_array_to_slice(slices));
}

StringReference allocate_and_join_string(CompileUnit* restrict unit, StringSlice slice)
{
    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_position = arena->position;
    let arena_top = arena_byte_pointer + arena_position;

    u64 string_length = 0;

    for (u64 i = 0; i < slice.length; i += 1)
    {
        let string = slice.pointer[i];
        assert((!((string.pointer > arena_bottom) & (string.pointer < arena_top))) || slice.length != 1); // Repeated string
        assert(string.length <= UINT32_MAX);
        string_length += string.length;
    }

    StringReference result = {};

    u64 i = sizeof(Arena);
    static_assert(alignof(Arena) >= alignof(u32));
    while (i < arena_position)
    {
        let byte_pointer = arena_byte_pointer + i;
        let length = *(u32*)byte_pointer;

        if (length == string_length)
        {
            u64 offset = sizeof(u32);
            bool is_equal = true;
            for (u64 string_i = 0; string_i < slice.length; string_i += 1)
            {
                let string = slice.pointer[string_i];
                is_equal = memcmp(string.pointer, byte_pointer + offset, string.length) == 0;
                offset += string.length;
                if (!is_equal)
                {
                    break;
                }
            }

            if (is_equal)
            {
                result = (StringReference) {
                    .v = (u32)(i + 1),
                };
                break;
            }
        }

        i += align_forward(length + 1 + sizeof(u32), alignof(u32));
    }

    if (!is_ref_valid(result))
    {
        let allocation_size = string_length + sizeof(u32) + 1;
        let string = (char* restrict) arena_allocate_bytes(arena, allocation_size, alignof(u32));
        assert(string_length < UINT32_MAX);
        *(u32*)string = (u32)string_length;
        let pointer = string + 4;

        for (u64 i = 0; i < slice.length; i += 1)
        {
            let string = slice.pointer[i];
            memcpy(pointer, string.pointer, string.length);
            pointer += string.length;
        }

        *pointer = 0;

        let big_offset = string - arena_byte_pointer;
        assert(big_offset + 1 < UINT32_MAX);
        let offset = (u32)big_offset;
        result = (StringReference) {
            .v = offset + 1,
        };
    }

    return result;
}

StringReference allocate_string_if_needed(CompileUnit* restrict unit, str s)
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
        return allocate_string(unit, s);
    }
}

static void crunch_file(CompileUnit* restrict unit, str path)
{
    str content = file_read(unit_arena(unit, UNIT_ARENA_FILE_CONTENT), path, (FileReadOptions){
        .start_padding = sizeof(u32),
        .start_alignment = alignof(u32),
    });
    assert(content.length < UINT32_MAX);
    *((u32*)content.pointer - 1) = content.length;

    let path_reference = allocate_string_if_needed(unit, path);

    let arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
    let scope = new_scope(unit);
    let file = arena_allocate(arena, File, 1);
    let file_reference = file_reference_from_pointer(unit, file);

    if (is_ref_valid(unit->last_file))
    {
        todo();
    }
    else
    {
        assert(!is_ref_valid(unit->first_file));
        unit->first_file = file_reference;
    }

    unit->last_file = file_reference;

    *scope = (Scope)
    {
        .parent = unit->scope,
        .id = SCOPE_ID_FILE,
        .file = file_reference,
    };

    *file = (File) {
        .content = content,
        .path = path_reference,
        .scope = scope_reference_from_pointer(unit, scope),
    };

    let tl = lex(unit_arena(unit, UNIT_ARENA_TOKEN), unit_arena(unit, UNIT_ARENA_STRING), content.pointer, content.length);
    let first_tld = parse(unit, file, tl);
    analyze(unit, first_tld);
}

void* thread_worker(void* arg)
{
    u64 result_code = 0;
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

    return result;
}
