
#include "fe.h"
#include "crypto_additions.h"

void ge_p3_to_montx(fe montx, const ge_p3 *ed)
{
  /* 
     mont_x = (ed_y + 1) / (1 - ed_y)

     mont_x = (ed_y + ed_z) / (ed_z - ed_y)

     NOTE: ed_y=1 is converted to mont_x=0 since fe_invert is mod-exp
  */

  fe edy_plus_one, one_minus_edy, inv_one_minus_edy;

  fe_add(edy_plus_one, ed->Y, ed->Z);
  fe_sub(one_minus_edy, ed->Z, ed->Y);  
  fe_invert(inv_one_minus_edy, one_minus_edy);
  fe_mul(montx, edy_plus_one, inv_one_minus_edy);
}

