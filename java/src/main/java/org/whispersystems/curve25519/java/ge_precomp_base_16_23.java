package org.whispersystems.curve25519.java;

public class ge_precomp_base_16_23 {
  /* base[i][j] = (j+1)*256^i*B */
  static ge_precomp base[][];

  static {
//CONVERT #include "base.h"
    base = new ge_precomp[32][8];

    base[16][0] = new ge_precomp(
        new int[]  { 11374242,12660715,17861383,-12540833,10935568,1099227,-13886076,-9091740,-27727044,11358504 },
        new int[]  { -12730809,10311867,1510375,10778093,-2119455,-9145702,32676003,11149336,-26123651,4985768 },
        new int[]  { -19096303,341147,-6197485,-239033,15756973,-8796662,-983043,13794114,-19414307,-15621255 }
    );
    base[16][1] = new ge_precomp(
        new int[]  { 6490081,11940286,25495923,-7726360,8668373,-8751316,3367603,6970005,-1691065,-9004790 },
        new int[]  { 1656497,13457317,15370807,6364910,13605745,8362338,-19174622,-5475723,-16796596,-5031438 },
        new int[]  { -22273315,-13524424,-64685,-4334223,-18605636,-10921968,-20571065,-7007978,-99853,-10237333 }
    );
    base[16][2] = new ge_precomp(
        new int[]  { 17747465,10039260,19368299,-4050591,-20630635,-16041286,31992683,-15857976,-29260363,-5511971 },
        new int[]  { 31932027,-4986141,-19612382,16366580,22023614,88450,11371999,-3744247,4882242,-10626905 },
        new int[]  { 29796507,37186,19818052,10115756,-11829032,3352736,18551198,3272828,-5190932,-4162409 }
    );
    base[16][3] = new ge_precomp(
        new int[]  { 12501286,4044383,-8612957,-13392385,-32430052,5136599,-19230378,-3529697,330070,-3659409 },
        new int[]  { 6384877,2899513,17807477,7663917,-2358888,12363165,25366522,-8573892,-271295,12071499 },
        new int[]  { -8365515,-4042521,25133448,-4517355,-6211027,2265927,-32769618,1936675,-5159697,3829363 }
    );
    base[16][4] = new ge_precomp(
        new int[]  { 28425966,-5835433,-577090,-4697198,-14217555,6870930,7921550,-6567787,26333140,14267664 },
        new int[]  { -11067219,11871231,27385719,-10559544,-4585914,-11189312,10004786,-8709488,-21761224,8930324 },
        new int[]  { -21197785,-16396035,25654216,-1725397,12282012,11008919,1541940,4757911,-26491501,-16408940 }
    );
    base[16][5] = new ge_precomp(
        new int[]  { 13537262,-7759490,-20604840,10961927,-5922820,-13218065,-13156584,6217254,-15943699,13814990 },
        new int[]  { -17422573,15157790,18705543,29619,24409717,-260476,27361681,9257833,-1956526,-1776914 },
        new int[]  { -25045300,-10191966,15366585,15166509,-13105086,8423556,-29171540,12361135,-18685978,4578290 }
    );
    base[16][6] = new ge_precomp(
        new int[]  { 24579768,3711570,1342322,-11180126,-27005135,14124956,-22544529,14074919,21964432,8235257 },
        new int[]  { -6528613,-2411497,9442966,-5925588,12025640,-1487420,-2981514,-1669206,13006806,2355433 },
        new int[]  { -16304899,-13605259,-6632427,-5142349,16974359,-10911083,27202044,1719366,1141648,-12796236 }
    );
    base[16][7] = new ge_precomp(
        new int[]  { -12863944,-13219986,-8318266,-11018091,-6810145,-4843894,13475066,-3133972,32674895,13715045 },
        new int[]  { 11423335,-5468059,32344216,8962751,24989809,9241752,-13265253,16086212,-28740881,-15642093 },
        new int[]  { -1409668,12530728,-6368726,10847387,19531186,-14132160,-11709148,7791794,-27245943,4383347 }
    );
    base[17][0] = new ge_precomp(
        new int[]  { -28970898,5271447,-1266009,-9736989,-12455236,16732599,-4862407,-4906449,27193557,6245191 },
        new int[]  { -15193956,5362278,-1783893,2695834,4960227,12840725,23061898,3260492,22510453,8577507 },
        new int[]  { -12632451,11257346,-32692994,13548177,-721004,10879011,31168030,13952092,-29571492,-3635906 }
    );
    base[17][1] = new ge_precomp(
        new int[]  { 3877321,-9572739,32416692,5405324,-11004407,-13656635,3759769,11935320,5611860,8164018 },
        new int[]  { -16275802,14667797,15906460,12155291,-22111149,-9039718,32003002,-8832289,5773085,-8422109 },
        new int[]  { -23788118,-8254300,1950875,8937633,18686727,16459170,-905725,12376320,31632953,190926 }
    );
    base[17][2] = new ge_precomp(
        new int[]  { -24593607,-16138885,-8423991,13378746,14162407,6901328,-8288749,4508564,-25341555,-3627528 },
        new int[]  { 8884438,-5884009,6023974,10104341,-6881569,-4941533,18722941,-14786005,-1672488,827625 },
        new int[]  { -32720583,-16289296,-32503547,7101210,13354605,2659080,-1800575,-14108036,-24878478,1541286 }
    );
    base[17][3] = new ge_precomp(
        new int[]  { 2901347,-1117687,3880376,-10059388,-17620940,-3612781,-21802117,-3567481,20456845,-1885033 },
        new int[]  { 27019610,12299467,-13658288,-1603234,-12861660,-4861471,-19540150,-5016058,29439641,15138866 },
        new int[]  { 21536104,-6626420,-32447818,-10690208,-22408077,5175814,-5420040,-16361163,7779328,109896 }
    );
    base[17][4] = new ge_precomp(
        new int[]  { 30279744,14648750,-8044871,6425558,13639621,-743509,28698390,12180118,23177719,-554075 },
        new int[]  { 26572847,3405927,-31701700,12890905,-19265668,5335866,-6493768,2378492,4439158,-13279347 },
        new int[]  { -22716706,3489070,-9225266,-332753,18875722,-1140095,14819434,-12731527,-17717757,-5461437 }
    );
    base[17][5] = new ge_precomp(
        new int[]  { -5056483,16566551,15953661,3767752,-10436499,15627060,-820954,2177225,8550082,-15114165 },
        new int[]  { -18473302,16596775,-381660,15663611,22860960,15585581,-27844109,-3582739,-23260460,-8428588 },
        new int[]  { -32480551,15707275,-8205912,-5652081,29464558,2713815,-22725137,15860482,-21902570,1494193 }
    );
    base[17][6] = new ge_precomp(
        new int[]  { -19562091,-14087393,-25583872,-9299552,13127842,759709,21923482,16529112,8742704,12967017 },
        new int[]  { -28464899,1553205,32536856,-10473729,-24691605,-406174,-8914625,-2933896,-29903758,15553883 },
        new int[]  { 21877909,3230008,9881174,10539357,-4797115,2841332,11543572,14513274,19375923,-12647961 }
    );
    base[17][7] = new ge_precomp(
        new int[]  { 8832269,-14495485,13253511,5137575,5037871,4078777,24880818,-6222716,2862653,9455043 },
        new int[]  { 29306751,5123106,20245049,-14149889,9592566,8447059,-2077124,-2990080,15511449,4789663 },
        new int[]  { -20679756,7004547,8824831,-9434977,-4045704,-3750736,-5754762,108893,23513200,16652362 }
    );
    base[18][0] = new ge_precomp(
        new int[]  { -33256173,4144782,-4476029,-6579123,10770039,-7155542,-6650416,-12936300,-18319198,10212860 },
        new int[]  { 2756081,8598110,7383731,-6859892,22312759,-1105012,21179801,2600940,-9988298,-12506466 },
        new int[]  { -24645692,13317462,-30449259,-15653928,21365574,-10869657,11344424,864440,-2499677,-16710063 }
    );
    base[18][1] = new ge_precomp(
        new int[]  { -26432803,6148329,-17184412,-14474154,18782929,-275997,-22561534,211300,2719757,4940997 },
        new int[]  { -1323882,3911313,-6948744,14759765,-30027150,7851207,21690126,8518463,26699843,5276295 },
        new int[]  { -13149873,-6429067,9396249,365013,24703301,-10488939,1321586,149635,-15452774,7159369 }
    );
    base[18][2] = new ge_precomp(
        new int[]  { 9987780,-3404759,17507962,9505530,9731535,-2165514,22356009,8312176,22477218,-8403385 },
        new int[]  { 18155857,-16504990,19744716,9006923,15154154,-10538976,24256460,-4864995,-22548173,9334109 },
        new int[]  { 2986088,-4911893,10776628,-3473844,10620590,-7083203,-21413845,14253545,-22587149,536906 }
    );
    base[18][3] = new ge_precomp(
        new int[]  { 4377756,8115836,24567078,15495314,11625074,13064599,7390551,10589625,10838060,-15420424 },
        new int[]  { -19342404,867880,9277171,-3218459,-14431572,-1986443,19295826,-15796950,6378260,699185 },
        new int[]  { 7895026,4057113,-7081772,-13077756,-17886831,-323126,-716039,15693155,-5045064,-13373962 }
    );
    base[18][4] = new ge_precomp(
        new int[]  { -7737563,-5869402,-14566319,-7406919,11385654,13201616,31730678,-10962840,-3918636,-9669325 },
        new int[]  { 10188286,-15770834,-7336361,13427543,22223443,14896287,30743455,7116568,-21786507,5427593 },
        new int[]  { 696102,13206899,27047647,-10632082,15285305,-9853179,10798490,-4578720,19236243,12477404 }
    );
    base[18][5] = new ge_precomp(
        new int[]  { -11229439,11243796,-17054270,-8040865,-788228,-8167967,-3897669,11180504,-23169516,7733644 },
        new int[]  { 17800790,-14036179,-27000429,-11766671,23887827,3149671,23466177,-10538171,10322027,15313801 },
        new int[]  { 26246234,11968874,32263343,-5468728,6830755,-13323031,-15794704,-101982,-24449242,10890804 }
    );
    base[18][6] = new ge_precomp(
        new int[]  { -31365647,10271363,-12660625,-6267268,16690207,-13062544,-14982212,16484931,25180797,-5334884 },
        new int[]  { -586574,10376444,-32586414,-11286356,19801893,10997610,2276632,9482883,316878,13820577 },
        new int[]  { -9882808,-4510367,-2115506,16457136,-11100081,11674996,30756178,-7515054,30696930,-3712849 }
    );
    base[18][7] = new ge_precomp(
        new int[]  { 32988917,-9603412,12499366,7910787,-10617257,-11931514,-7342816,-9985397,-32349517,7392473 },
        new int[]  { -8855661,15927861,9866406,-3649411,-2396914,-16655781,-30409476,-9134995,25112947,-2926644 },
        new int[]  { -2504044,-436966,25621774,-5678772,15085042,-5479877,-24884878,-13526194,5537438,-13914319 }
    );
    base[19][0] = new ge_precomp(
        new int[]  { -11225584,2320285,-9584280,10149187,-33444663,5808648,-14876251,-1729667,31234590,6090599 },
        new int[]  { -9633316,116426,26083934,2897444,-6364437,-2688086,609721,15878753,-6970405,-9034768 },
        new int[]  { -27757857,247744,-15194774,-9002551,23288161,-10011936,-23869595,6503646,20650474,1804084 }
    );
    base[19][1] = new ge_precomp(
        new int[]  { -27589786,15456424,8972517,8469608,15640622,4439847,3121995,-10329713,27842616,-202328 },
        new int[]  { -15306973,2839644,22530074,10026331,4602058,5048462,28248656,5031932,-11375082,12714369 },
        new int[]  { 20807691,-7270825,29286141,11421711,-27876523,-13868230,-21227475,1035546,-19733229,12796920 }
    );
    base[19][2] = new ge_precomp(
        new int[]  { 12076899,-14301286,-8785001,-11848922,-25012791,16400684,-17591495,-12899438,3480665,-15182815 },
        new int[]  { -32361549,5457597,28548107,7833186,7303070,-11953545,-24363064,-15921875,-33374054,2771025 },
        new int[]  { -21389266,421932,26597266,6860826,22486084,-6737172,-17137485,-4210226,-24552282,15673397 }
    );
    base[19][3] = new ge_precomp(
        new int[]  { -20184622,2338216,19788685,-9620956,-4001265,-8740893,-20271184,4733254,3727144,-12934448 },
        new int[]  { 6120119,814863,-11794402,-622716,6812205,-15747771,2019594,7975683,31123697,-10958981 },
        new int[]  { 30069250,-11435332,30434654,2958439,18399564,-976289,12296869,9204260,-16432438,9648165 }
    );
    base[19][4] = new ge_precomp(
        new int[]  { 32705432,-1550977,30705658,7451065,-11805606,9631813,3305266,5248604,-26008332,-11377501 },
        new int[]  { 17219865,2375039,-31570947,-5575615,-19459679,9219903,294711,15298639,2662509,-16297073 },
        new int[]  { -1172927,-7558695,-4366770,-4287744,-21346413,-8434326,32087529,-1222777,32247248,-14389861 }
    );
    base[19][5] = new ge_precomp(
        new int[]  { 14312628,1221556,17395390,-8700143,-4945741,-8684635,-28197744,-9637817,-16027623,-13378845 },
        new int[]  { -1428825,-9678990,-9235681,6549687,-7383069,-468664,23046502,9803137,17597934,2346211 },
        new int[]  { 18510800,15337574,26171504,981392,-22241552,7827556,-23491134,-11323352,3059833,-11782870 }
    );
    base[19][6] = new ge_precomp(
        new int[]  { 10141598,6082907,17829293,-1947643,9830092,13613136,-25556636,-5544586,-33502212,3592096 },
        new int[]  { 33114168,-15889352,-26525686,-13343397,33076705,8716171,1151462,1521897,-982665,-6837803 },
        new int[]  { -32939165,-4255815,23947181,-324178,-33072974,-12305637,-16637686,3891704,26353178,693168 }
    );
    base[19][7] = new ge_precomp(
        new int[]  { 30374239,1595580,-16884039,13186931,4600344,406904,9585294,-400668,31375464,14369965 },
        new int[]  { -14370654,-7772529,1510301,6434173,-18784789,-6262728,32732230,-13108839,17901441,16011505 },
        new int[]  { 18171223,-11934626,-12500402,15197122,-11038147,-15230035,-19172240,-16046376,8764035,12309598 }
    );
    base[20][0] = new ge_precomp(
        new int[]  { 5975908,-5243188,-19459362,-9681747,-11541277,14015782,-23665757,1228319,17544096,-10593782 },
        new int[]  { 5811932,-1715293,3442887,-2269310,-18367348,-8359541,-18044043,-15410127,-5565381,12348900 },
        new int[]  { -31399660,11407555,25755363,6891399,-3256938,14872274,-24849353,8141295,-10632534,-585479 }
    );
    base[20][1] = new ge_precomp(
        new int[]  { -12675304,694026,-5076145,13300344,14015258,-14451394,-9698672,-11329050,30944593,1130208 },
        new int[]  { 8247766,-6710942,-26562381,-7709309,-14401939,-14648910,4652152,2488540,23550156,-271232 },
        new int[]  { 17294316,-3788438,7026748,15626851,22990044,113481,2267737,-5908146,-408818,-137719 }
    );
    base[20][2] = new ge_precomp(
        new int[]  { 16091085,-16253926,18599252,7340678,2137637,-1221657,-3364161,14550936,3260525,-7166271 },
        new int[]  { -4910104,-13332887,18550887,10864893,-16459325,-7291596,-23028869,-13204905,-12748722,2701326 },
        new int[]  { -8574695,16099415,4629974,-16340524,-20786213,-6005432,-10018363,9276971,11329923,1862132 }
    );
    base[20][3] = new ge_precomp(
        new int[]  { 14763076,-15903608,-30918270,3689867,3511892,10313526,-21951088,12219231,-9037963,-940300 },
        new int[]  { 8894987,-3446094,6150753,3013931,301220,15693451,-31981216,-2909717,-15438168,11595570 },
        new int[]  { 15214962,3537601,-26238722,-14058872,4418657,-15230761,13947276,10730794,-13489462,-4363670 }
    );
    base[20][4] = new ge_precomp(
        new int[]  { -2538306,7682793,32759013,263109,-29984731,-7955452,-22332124,-10188635,977108,699994 },
        new int[]  { -12466472,4195084,-9211532,550904,-15565337,12917920,19118110,-439841,-30534533,-14337913 },
        new int[]  { 31788461,-14507657,4799989,7372237,8808585,-14747943,9408237,-10051775,12493932,-5409317 }
    );
    base[20][5] = new ge_precomp(
        new int[]  { -25680606,5260744,-19235809,-6284470,-3695942,16566087,27218280,2607121,29375955,6024730 },
        new int[]  { 842132,-2794693,-4763381,-8722815,26332018,-12405641,11831880,6985184,-9940361,2854096 },
        new int[]  { -4847262,-7969331,2516242,-5847713,9695691,-7221186,16512645,960770,12121869,16648078 }
    );
    base[20][6] = new ge_precomp(
        new int[]  { -15218652,14667096,-13336229,2013717,30598287,-464137,-31504922,-7882064,20237806,2838411 },
        new int[]  { -19288047,4453152,15298546,-16178388,22115043,-15972604,12544294,-13470457,1068881,-12499905 },
        new int[]  { -9558883,-16518835,33238498,13506958,30505848,-1114596,-8486907,-2630053,12521378,4845654 }
    );
    base[20][7] = new ge_precomp(
        new int[]  { -28198521,10744108,-2958380,10199664,7759311,-13088600,3409348,-873400,-6482306,-12885870 },
        new int[]  { -23561822,6230156,-20382013,10655314,-24040585,-11621172,10477734,-1240216,-3113227,13974498 },
        new int[]  { 12966261,15550616,-32038948,-1615346,21025980,-629444,5642325,7188737,18895762,12629579 }
    );
    base[21][0] = new ge_precomp(
        new int[]  { 14741879,-14946887,22177208,-11721237,1279741,8058600,11758140,789443,32195181,3895677 },
        new int[]  { 10758205,15755439,-4509950,9243698,-4879422,6879879,-2204575,-3566119,-8982069,4429647 },
        new int[]  { -2453894,15725973,-20436342,-10410672,-5803908,-11040220,-7135870,-11642895,18047436,-15281743 }
    );
    base[21][1] = new ge_precomp(
        new int[]  { -25173001,-11307165,29759956,11776784,-22262383,-15820455,10993114,-12850837,-17620701,-9408468 },
        new int[]  { 21987233,700364,-24505048,14972008,-7774265,-5718395,32155026,2581431,-29958985,8773375 },
        new int[]  { -25568350,454463,-13211935,16126715,25240068,8594567,20656846,12017935,-7874389,-13920155 }
    );
    base[21][2] = new ge_precomp(
        new int[]  { 6028182,6263078,-31011806,-11301710,-818919,2461772,-31841174,-5468042,-1721788,-2776725 },
        new int[]  { -12278994,16624277,987579,-5922598,32908203,1248608,7719845,-4166698,28408820,6816612 },
        new int[]  { -10358094,-8237829,19549651,-12169222,22082623,16147817,20613181,13982702,-10339570,5067943 }
    );
    base[21][3] = new ge_precomp(
        new int[]  { -30505967,-3821767,12074681,13582412,-19877972,2443951,-19719286,12746132,5331210,-10105944 },
        new int[]  { 30528811,3601899,-1957090,4619785,-27361822,-15436388,24180793,-12570394,27679908,-1648928 },
        new int[]  { 9402404,-13957065,32834043,10838634,-26580150,-13237195,26653274,-8685565,22611444,-12715406 }
    );
    base[21][4] = new ge_precomp(
        new int[]  { 22190590,1118029,22736441,15130463,-30460692,-5991321,19189625,-4648942,4854859,6622139 },
        new int[]  { -8310738,-2953450,-8262579,-3388049,-10401731,-271929,13424426,-3567227,26404409,13001963 },
        new int[]  { -31241838,-15415700,-2994250,8939346,11562230,-12840670,-26064365,-11621720,-15405155,11020693 }
    );
    base[21][5] = new ge_precomp(
        new int[]  { 1866042,-7949489,-7898649,-10301010,12483315,13477547,3175636,-12424163,28761762,1406734 },
        new int[]  { -448555,-1777666,13018551,3194501,-9580420,-11161737,24760585,-4347088,25577411,-13378680 },
        new int[]  { -24290378,4759345,-690653,-1852816,2066747,10693769,-29595790,9884936,-9368926,4745410 }
    );
    base[21][6] = new ge_precomp(
        new int[]  { -9141284,6049714,-19531061,-4341411,-31260798,9944276,-15462008,-11311852,10931924,-11931931 },
        new int[]  { -16561513,14112680,-8012645,4817318,-8040464,-11414606,-22853429,10856641,-20470770,13434654 },
        new int[]  { 22759489,-10073434,-16766264,-1871422,13637442,-10168091,1765144,-12654326,28445307,-5364710 }
    );
    base[21][7] = new ge_precomp(
        new int[]  { 29875063,12493613,2795536,-3786330,1710620,15181182,-10195717,-8788675,9074234,1167180 },
        new int[]  { -26205683,11014233,-9842651,-2635485,-26908120,7532294,-18716888,-9535498,3843903,9367684 },
        new int[]  { -10969595,-6403711,9591134,9582310,11349256,108879,16235123,8601684,-139197,4242895 }
    );
    base[22][0] = new ge_precomp(
        new int[]  { 22092954,-13191123,-2042793,-11968512,32186753,-11517388,-6574341,2470660,-27417366,16625501 },
        new int[]  { -11057722,3042016,13770083,-9257922,584236,-544855,-7770857,2602725,-27351616,14247413 },
        new int[]  { 6314175,-10264892,-32772502,15957557,-10157730,168750,-8618807,14290061,27108877,-1180880 }
    );
    base[22][1] = new ge_precomp(
        new int[]  { -8586597,-7170966,13241782,10960156,-32991015,-13794596,33547976,-11058889,-27148451,981874 },
        new int[]  { 22833440,9293594,-32649448,-13618667,-9136966,14756819,-22928859,-13970780,-10479804,-16197962 },
        new int[]  { -7768587,3326786,-28111797,10783824,19178761,14905060,22680049,13906969,-15933690,3797899 }
    );
    base[22][2] = new ge_precomp(
        new int[]  { 21721356,-4212746,-12206123,9310182,-3882239,-13653110,23740224,-2709232,20491983,-8042152 },
        new int[]  { 9209270,-15135055,-13256557,-6167798,-731016,15289673,25947805,15286587,30997318,-6703063 },
        new int[]  { 7392032,16618386,23946583,-8039892,-13265164,-1533858,-14197445,-2321576,17649998,-250080 }
    );
    base[22][3] = new ge_precomp(
        new int[]  { -9301088,-14193827,30609526,-3049543,-25175069,-1283752,-15241566,-9525724,-2233253,7662146 },
        new int[]  { -17558673,1763594,-33114336,15908610,-30040870,-12174295,7335080,-8472199,-3174674,3440183 },
        new int[]  { -19889700,-5977008,-24111293,-9688870,10799743,-16571957,40450,-4431835,4862400,1133 }
    );
    base[22][4] = new ge_precomp(
        new int[]  { -32856209,-7873957,-5422389,14860950,-16319031,7956142,7258061,311861,-30594991,-7379421 },
        new int[]  { -3773428,-1565936,28985340,7499440,24445838,9325937,29727763,16527196,18278453,15405622 },
        new int[]  { -4381906,8508652,-19898366,-3674424,-5984453,15149970,-13313598,843523,-21875062,13626197 }
    );
    base[22][5] = new ge_precomp(
        new int[]  { 2281448,-13487055,-10915418,-2609910,1879358,16164207,-10783882,3953792,13340839,15928663 },
        new int[]  { 31727126,-7179855,-18437503,-8283652,2875793,-16390330,-25269894,-7014826,-23452306,5964753 },
        new int[]  { 4100420,-5959452,-17179337,6017714,-18705837,12227141,-26684835,11344144,2538215,-7570755 }
    );
    base[22][6] = new ge_precomp(
        new int[]  { -9433605,6123113,11159803,-2156608,30016280,14966241,-20474983,1485421,-629256,-15958862 },
        new int[]  { -26804558,4260919,11851389,9658551,-32017107,16367492,-20205425,-13191288,11659922,-11115118 },
        new int[]  { 26180396,10015009,-30844224,-8581293,5418197,9480663,2231568,-10170080,33100372,-1306171 }
    );
    base[22][7] = new ge_precomp(
        new int[]  { 15121113,-5201871,-10389905,15427821,-27509937,-15992507,21670947,4486675,-5931810,-14466380 },
        new int[]  { 16166486,-9483733,-11104130,6023908,-31926798,-1364923,2340060,-16254968,-10735770,-10039824 },
        new int[]  { 28042865,-3557089,-12126526,12259706,-3717498,-6945899,6766453,-8689599,18036436,5803270 }
    );
    base[23][0] = new ge_precomp(
        new int[]  { -817581,6763912,11803561,1585585,10958447,-2671165,23855391,4598332,-6159431,-14117438 },
        new int[]  { -31031306,-14256194,17332029,-2383520,31312682,-5967183,696309,50292,-20095739,11763584 },
        new int[]  { -594563,-2514283,-32234153,12643980,12650761,14811489,665117,-12613632,-19773211,-10713562 }
    );
    base[23][1] = new ge_precomp(
        new int[]  { 30464590,-11262872,-4127476,-12734478,19835327,-7105613,-24396175,2075773,-17020157,992471 },
        new int[]  { 18357185,-6994433,7766382,16342475,-29324918,411174,14578841,8080033,-11574335,-10601610 },
        new int[]  { 19598397,10334610,12555054,2555664,18821899,-10339780,21873263,16014234,26224780,16452269 }
    );
    base[23][2] = new ge_precomp(
        new int[]  { -30223925,5145196,5944548,16385966,3976735,2009897,-11377804,-7618186,-20533829,3698650 },
        new int[]  { 14187449,3448569,-10636236,-10810935,-22663880,-3433596,7268410,-10890444,27394301,12015369 },
        new int[]  { 19695761,16087646,28032085,12999827,6817792,11427614,20244189,-1312777,-13259127,-3402461 }
    );
    base[23][3] = new ge_precomp(
        new int[]  { 30860103,12735208,-1888245,-4699734,-16974906,2256940,-8166013,12298312,-8550524,-10393462 },
        new int[]  { -5719826,-11245325,-1910649,15569035,26642876,-7587760,-5789354,-15118654,-4976164,12651793 },
        new int[]  { -2848395,9953421,11531313,-5282879,26895123,-12697089,-13118820,-16517902,9768698,-2533218 }
    );
    base[23][4] = new ge_precomp(
        new int[]  { -24719459,1894651,-287698,-4704085,15348719,-8156530,32767513,12765450,4940095,10678226 },
        new int[]  { 18860224,15980149,-18987240,-1562570,-26233012,-11071856,-7843882,13944024,-24372348,16582019 },
        new int[]  { -15504260,4970268,-29893044,4175593,-20993212,-2199756,-11704054,15444560,-11003761,7989037 }
    );
    base[23][5] = new ge_precomp(
        new int[]  { 31490452,5568061,-2412803,2182383,-32336847,4531686,-32078269,6200206,-19686113,-14800171 },
        new int[]  { -17308668,-15879940,-31522777,-2831,-32887382,16375549,8680158,-16371713,28550068,-6857132 },
        new int[]  { -28126887,-5688091,16837845,-1820458,-6850681,12700016,-30039981,4364038,1155602,5988841 }
    );
    base[23][6] = new ge_precomp(
        new int[]  { 21890435,-13272907,-12624011,12154349,-7831873,15300496,23148983,-4470481,24618407,8283181 },
        new int[]  { -33136107,-10512751,9975416,6841041,-31559793,16356536,3070187,-7025928,1466169,10740210 },
        new int[]  { -1509399,-15488185,-13503385,-10655916,32799044,909394,-13938903,-5779719,-32164649,-15327040 }
    );
    base[23][7] = new ge_precomp(
        new int[]  { 3960823,-14267803,-28026090,-15918051,-19404858,13146868,15567327,951507,-3260321,-573935 },
        new int[]  { 24740841,5052253,-30094131,8961361,25877428,6165135,-24368180,14397372,-7380369,-6144105 },
        new int[]  { -28888365,3510803,-28103278,-1158478,-11238128,-10631454,-15441463,-14453128,-1625486,-6494814 }
    );
  }
}
