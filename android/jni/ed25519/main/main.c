#include "tests.h"
#include "gen_tests.h"


int main(int argc, char* argv[])
{
  generalized_all_fast_tests(0);
  all_fast_tests(0);

  generalized_xveddsa_slow_test(0, 10000);
  curvesigs_slow_test(0,           10000);
  xeddsa_slow_test(0,              10000);
  xeddsa_to_curvesigs_slow_test(0, 10000);
  vxeddsa_slow_test(0,             10000);
  return 0;
}
