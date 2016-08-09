
#include "fe.h"
#include "crypto_additions.h"

void fe_montx_to_edy(fe edy, const fe montx)
{
  /* 
     ed_y = (mont_x - 1) / (mont_x + 1)

     NOTE: mont_x=-1 is converted to ed_y=0 since fe_invert is mod-exp
  */
  fe one, montx_minus_one, montx_plus_one, inv_montx_plus_one;

  fe_1(one);
  fe_sub(montx_minus_one, montx, one);
  fe_add(montx_plus_one, montx, one);
  fe_invert(inv_montx_plus_one, montx_plus_one);
  fe_mul(edy, montx_minus_one, inv_montx_plus_one);
}
