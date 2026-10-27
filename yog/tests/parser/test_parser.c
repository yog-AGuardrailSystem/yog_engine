#include "../../src/parser/parser.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    const char source[] =
        "fact role(alice, admin)\n"
        "rule can_delete(User, DB):\n"
        "    role(User, admin)\n"
        "    environment(DB, development)\n"
        "    User != nobody\n"
        "    not revoked(User)\n"
        "allow can_read(User, File):\n"
        "    role(User, reader)\n"
        "query can_delete(alice, database_1)\n";
    Lexer lexer;
    YogProgram *program = NULL;
    YogParseError error;
    YogParseStatus status;
    size_t statement_count;
    size_t goal_count;

    lexer_init(&lexer, source, strlen(source));
    status = yog_parse(&lexer, &program, &error);
    if (status != YOG_PARSE_OK) {
        (void)fprintf(stderr, "%s at %d:%d: %s\n",
                      yog_parse_status_name(status), error.line,
                      error.column, error.message);
        return 1;
    }

    statement_count = program->statement_count;
    goal_count = program->statements[1].as.clause.body.goal_count;
    if (statement_count != 4 || goal_count != 4) {
        (void)fprintf(stderr, "Unexpected AST shape: %zu statements, %zu rule goals\n",
                      statement_count, goal_count);
        yog_program_free(program);
        return 1;
    }
    (void)printf("PASS: %zu statements; rule contains %zu goals\n",
                 statement_count, goal_count);
    yog_program_free(program);
    return 0;
}
