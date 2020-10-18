#include "config.h"
#include "torture.h"

#ifdef HAVE_ARGP_H
#include <argp.h>

const char *argp_program_version = "libssh test 0.2";
const char *argp_program_bug_address = "<csync-devel@csync.org>";

static char **cmdline;

/* Program documentation. */
static char doc[] = "libssh test test";

/* The options we understand. */
static struct argp_option options[] = {
  {
    .name  = "verbose",
    .key   = 'v',
    .arg   = NULL,
    .flags = 0,
    .doc   = "Make libssh test more verbose",
    .group = 0
  },
  {NULL, 0, NULL, 0, NULL, 0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
   * know is a pointer to our arguments structure.
   */
  struct argument_s *arguments = state->input;

  /* arg is currently not used */
  (void) arg;

  switch (key) {
    case 'v':
      arguments->verbose++;
      break;
    case ARGP_KEY_ARG:
      /* End processing here. */
      arguments->pattern = state->argv[state->next - 1];
      cmdline = &state->argv [state->next - 1];
      state->next = state->argc;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

/* Our argp parser. */
/* static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL}; */
static struct argp argp = {options, parse_opt, NULL, doc, NULL, NULL, NULL};
#endif /* HAVE_ARGP_H */

void torture_cmdline_parse(int argc, char **argv, struct argument_s *arguments) {
  /*
   * Parse our arguments; every option seen by parse_opt will
   * be reflected in arguments.
   */
#ifdef HAVE_ARGP_H
  argp_parse(&argp, argc, argv, 0, 0, arguments);
#else
  (void) argc;
  (void) argv;
  (void) arguments;
#endif /* HAVE_ARGP_H */
}
