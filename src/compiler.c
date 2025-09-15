#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <compiler.h>
#include <lexer.h>
#include <parser.h>
#include <analysis.h>
#include <llvm_common.h>
#include <llvm_generate.h>
#include <llvm_optimize.h>
#include <llvm_emit.h>
#include <llvm_link.h>
#include <llvm-c/Core.h>

#include <stdatomic.h>
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

static str generate_path_internal(Arena* arena, str directory, str name, str extension)
{
    assert(name.pointer);
    str strings[] = {
        directory.pointer ? directory : S("./"),
        name,
        extension.pointer ? extension : S(""),
    };
    str file_path = arena_join_string(arena, string_array_to_slice(strings), true);
    return file_path;
}

static str generate_artifact_path(CompileUnit* unit, str extension)
{
    let original_directory_artifact_path = unit->artifact_directory_path;
    let artifact_path = original_directory_artifact_path.pointer ? original_directory_artifact_path : S("build/");
    let first_file = file_pointer_from_reference(unit, unit->first_file);
    str result = generate_path_internal(get_default_arena(unit), artifact_path, first_file->name, extension);
    return result;
}

static str generate_object_path(CompileUnit* unit)
{
    return generate_artifact_path(unit, S(".o"));
}

static str generate_executable_path(CompileUnit* unit)
{
    let result = generate_artifact_path(unit, (str){});
    unit->artifact_path = result;
    return result;
}

static CompilationResult llvm_compile_file(CompileUnit* unit, str path)
{
    return (CompilationResult){};
}

static void llvm_compile_unit(StringSlice paths)
{
    //let arena_init_start = take_timestamp();
    let arena = arena_create((ArenaInitialization){});
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
static u64 float_type_count = 5;
static u64 void_noreturn_type_count = 2;

u64 get_base_type_count()
{
    return classic_integer_type_count + big_integer_type_count + float_type_count + void_noreturn_type_count;
}

static void default_show_callback(void* context, str message)
{
    unused(context);
    os_file_write((FileDescriptor*)1, message);
}

static CompileUnit* compile_unit_create()
{
    let arena = arena_create((ArenaInitialization) {
        .count = UNIT_ARENA_COUNT,
    });

    let unit = arena_allocate(arena, CompileUnit, 1);
    *unit = (CompileUnit) {};
    let global_scope = unit->scope;
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    assert(type_arena->position == sizeof(Arena));

    let base_type_count = get_base_type_count();
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
            type += 1;
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

    assert(type == base_type_allocation + base_type_count);

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

    unit->has_debug_info = 1;
    unit->show_callback = &default_show_callback;
    unit->verbose = 0;

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
    let default_arena = get_default_arena(unit);
    let absolute_path = path_absolute(default_arena, path.pointer);
    str content = file_read(unit_arena(unit, UNIT_ARENA_FILE_CONTENT), absolute_path, (FileReadOptions){
        .start_padding = sizeof(u32),
        .start_alignment = alignof(u32),
    });
    assert(content.length < UINT32_MAX);
    *((u32*)content.pointer - 1) = content.length;

    let last_slash_index = str_last_ch(absolute_path, '/');
    assert(last_slash_index != string_no_match);
    let directory_path = (str){ absolute_path.pointer, last_slash_index };
    let file_name = (str){ absolute_path.pointer + last_slash_index + 1, absolute_path.length - last_slash_index - 1 };
    let name_nz = (str) { file_name.pointer, file_name.length - strlen(".bbb") };
    let name = arena_duplicate_string(default_arena, name_nz, true);

    let scope = new_scope(unit);
    let file = arena_allocate(default_arena, File, 1);
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
        .path = absolute_path,
        .directory = directory_path,
        .file_name = file_name,
        .name = name,
        .scope = scope_reference_from_pointer(unit, scope),
    };

    let tl = lex(unit, file);
    parse(unit, file, tl);
}

static void print_llvm_message(CompileUnit* restrict unit, str message)
{
    assert(message.pointer);
    unit_show(unit, message);
    LLVMDisposeMessage(message.pointer);
}

static bool compile_unit_internal(CompileUnit* unit, str path)
{
    bool result_code = 1;
    crunch_file(unit, path);
    analyze(unit);
    let generate = llvm_generate_ir(unit, true);

    if (unit->verbose & !!generate.module)
    {
        char* s = LLVMPrintModuleToString(generate.module);
        str module_str = { s, strlen(s) };
        print_llvm_message(unit, module_str);
    }

    if (generate.error_message.pointer)
    {
        print_llvm_message(unit, generate.error_message);
        result_code = 0;
    }
    else
    {
        LLVMOptimizationLevel llvm_optimization_level;
        switch (unit->build_mode)
        {
            break; case BUILD_MODE_DEBUG: llvm_optimization_level = LLVM_OPTIMIZATION_LEVEL_O0;
            break; case BUILD_MODE_SIZE: llvm_optimization_level = LLVM_OPTIMIZATION_LEVEL_Oz;
            break; case BUILD_MODE_SPEED: llvm_optimization_level = LLVM_OPTIMIZATION_LEVEL_O3;
            break; default: UNREACHABLE();
        }

        bool verify_each_pass = true;
        bool debug_logging = false;

        let error_message = llvm_optimize(generate.module, generate.target_machine, llvm_optimization_level, verify_each_pass, debug_logging);
        if (error_message)
        {
            todo();
        }
        else
        {
            let object_path = generate_object_path(unit);
            unit->object_path = object_path;
            LLVMCodeGenFileType type = LLVMObjectFile;
            let error_message = llvm_emit(generate.module, generate.target_machine, object_path, type);
            if (error_message.pointer)
            {
                todo();
            }
        }
    }

    return result_code;
}

static bool compile_unit(str path)
{
    let unit = compile_unit_create();
    return compile_unit_internal(unit, path);
}

static bool compile_and_link_single_unit_internal(CompileUnit* unit, str path)
{
    bool result = compile_unit_internal(unit, path);
    if (result)
    {
        CompileUnit* units[] = {
            unit,
        };
        let first_file = file_pointer_from_reference(unit, unit->first_file);

        str output_artifact_path = generate_executable_path(unit);
        str result_string = llvm_link_machine_code(get_default_arena(unit), unit_arena(unit, UNIT_ARENA_STRING), units, array_length(units), (LinkOptions) {
            .output_artifact_path = output_artifact_path,
        });

        result = result_string.pointer == 0;
        if (!result)
        {
            unit_show(unit, result_string);
        }
    }

    return result;
}

static CompileUnit* compile_and_link_single_unit(str path)
{
    let unit = compile_unit_create();
    if (compile_and_link_single_unit_internal(unit, path))
    {
        return unit;
    }
    else
    {
        return 0;
    }
}

static let test_source_path = S("tests/tests.bbb");

static CompileUnit* compile_tests()
{
    let result = compile_and_link_single_unit(test_source_path);
    return result;
}

static void* thread_worker(void* arg)
{
    return (void*)(u64)!compile_tests();
}

static void* llvm_initialization_thread(void*)
{
    llvm_initialize();
    return 0;
}

typedef enum CompilerCommand : u8
{
    COMPILER_COMMAND_TEST,
} CompilerCommand;

static CompilerCommand default_command = COMPILER_COMMAND_TEST;

static void compiler_test_log(void* context, str string)
{
}

static bool compiler_tests()
{
    let arena_init = (ArenaInitialization){};
    TestArguments test_arguments = {
        .arena = arena_create(arena_init),
        .show = &compiler_test_log,
    };
    let result = 
        lib_tests(&test_arguments) &
        parser_tests(&test_arguments) &
        analysis_tests(&test_arguments) &
        llvm_generation_tests(&test_arguments) &
        arena_destroy(test_arguments.arena, arena_init.count);
    return result;
}

static bool unit_run(CompileUnit* restrict unit, StringSlice slice, char** envp)
{
    char* arg_buffer[64];
    
    char** arguments = {};
    if (slice.length)
    {
        todo();
    }
    else
    {
        arguments = arg_buffer;
        arguments[0] = unit->artifact_path.pointer;
        arguments[1] = 0;
    }
    let result = os_execute(get_default_arena(unit), arguments, envp, (ExecutionOptions) {});
    return (result.termination_kind == TERMINATION_KIND_EXIT) & (result.termination_code == 0);
}

static bool process_command_line(int argc, const char* argv[], char** envp)
{
    assert(is_single_threaded);

    bool result = 1;
    let command = default_command;

    if ((argc != 0) & (argc != 1))
    {
        todo();
    }

    switch (command)
    {
        break; case COMPILER_COMMAND_TEST:
        {
#if BB_INCLUDE_TESTS
            result = compiler_tests();
#endif
            if (result)
            {
                pthread_t handle;
                let create_result = pthread_create(&handle, 0, &llvm_initialization_thread, 0);
                result = create_result == 0;

                if (result)
                {
                    let unit = compile_tests();
                    bool run_result = 0;
                    if (unit)
                    {
                        run_result = unit_run(unit, (StringSlice){}, envp);
                    }
                    void* return_value = 0;
                    let join_result = pthread_join(handle, &return_value);
                    result = (unit != 0) & (join_result == 0) & (return_value == 0) & (run_result);
                }
            }
        }
        break; default:
        {
            result = 0;
        }
    }

    return result;
}

bool compiler_main(int argc, const char* argv[], char** envp)
{
    os_init();

    return process_command_line(argc, argv, envp);
}
