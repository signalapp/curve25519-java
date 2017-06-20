#ifndef __GEN_TESTS_H__
#define __GEN_TESTS_H__

/* silent = 0 : prints info+error messages to stdout, abort() on test failure
 * silent = 1 : returns 0 for success, anything else for failure 
 * iterations : hardcoded known-good values are at 10000, so run at least this many
 */

int generalized_xeddsa_fast_test(int silent);
int generalized_xveddsa_fast_test(int silent);

int generalized_xveddsa_slow_test(int silent, int iterations);

int generalized_all_fast_tests(int silent);

#endif
