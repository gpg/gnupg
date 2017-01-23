/* sqrtu32.c - Return the very approximate sqrt of an unsigned integer.
 *
 * This file by g10 Code GmbH
 *
 * To the extent possible under law, the person who associated CC0 with
 * g10 Code GmbH has waived all copyright and related or neighboring rights
 * to this file.
 *
 * You should have received a copy of the CC0 legalcode along with this
 * work.  If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
 */

/* The R code to generate the following table.  */
#if 0
{
  m = 2^32 - 1
  last.i = 0
  last.sqrt = 0
  i = 0
  while (i < m) {
    if (sqrt(i) - last.sqrt > 0.05 * last.sqrt) {
      cat(paste0("  if (i <= ", last.i, "u) return ", last.sqrt, ";\n"));
      last.i = i
      last.sqrt = sqrt(i)
    }
    i = i + max(1, floor(last.sqrt / 10))
  }
  cat(paste0("  return ", sqrt(m), ";\n"))
}
#endif

float
sqrtu32 (unsigned int i)
{
  if (i <= 0u) return 0;
  if (i <= 1u) return 1;
  if (i <= 2u) return 1.4142135623731;
  if (i <= 3u) return 1.73205080756888;
  if (i <= 4u) return 2;
  if (i <= 5u) return 2.23606797749979;
  if (i <= 6u) return 2.44948974278318;
  if (i <= 7u) return 2.64575131106459;
  if (i <= 8u) return 2.82842712474619;
  if (i <= 9u) return 3;
  if (i <= 10u) return 3.16227766016838;
  if (i <= 12u) return 3.46410161513775;
  if (i <= 14u) return 3.74165738677394;
  if (i <= 16u) return 4;
  if (i <= 18u) return 4.24264068711928;
  if (i <= 20u) return 4.47213595499958;
  if (i <= 23u) return 4.79583152331272;
  if (i <= 26u) return 5.09901951359278;
  if (i <= 29u) return 5.3851648071345;
  if (i <= 32u) return 5.65685424949238;
  if (i <= 36u) return 6;
  if (i <= 40u) return 6.32455532033676;
  if (i <= 45u) return 6.70820393249937;
  if (i <= 50u) return 7.07106781186548;
  if (i <= 56u) return 7.48331477354788;
  if (i <= 62u) return 7.87400787401181;
  if (i <= 69u) return 8.30662386291807;
  if (i <= 77u) return 8.77496438739212;
  if (i <= 85u) return 9.21954445729289;
  if (i <= 94u) return 9.69535971483266;
  if (i <= 104u) return 10.1980390271856;
  if (i <= 115u) return 10.7238052947636;
  if (i <= 127u) return 11.2694276695846;
  if (i <= 141u) return 11.8743420870379;
  if (i <= 156u) return 12.4899959967968;
  if (i <= 172u) return 13.114877048604;
  if (i <= 190u) return 13.7840487520902;
  if (i <= 210u) return 14.4913767461894;
  if (i <= 232u) return 15.2315462117278;
  if (i <= 256u) return 16;
  if (i <= 283u) return 16.8226038412607;
  if (i <= 313u) return 17.6918060129541;
  if (i <= 346u) return 18.6010752377383;
  if (i <= 382u) return 19.5448202856921;
  if (i <= 422u) return 20.5426385841741;
  if (i <= 466u) return 21.5870331449229;
  if (i <= 514u) return 22.6715680975093;
  if (i <= 568u) return 23.832750575626;
  if (i <= 628u) return 25.0599281722833;
  if (i <= 694u) return 26.343879744639;
  if (i <= 766u) return 27.6767050061961;
  if (i <= 846u) return 29.086079144498;
  if (i <= 934u) return 30.5614135798723;
  if (i <= 1030u) return 32.0936130717624;
  if (i <= 1138u) return 33.734255586866;
  if (i <= 1255u) return 35.4259791678367;
  if (i <= 1384u) return 37.2021504754766;
  if (i <= 1528u) return 39.0896405713841;
  if (i <= 1687u) return 41.0731055558257;
  if (i <= 1863u) return 43.1624837098145;
  if (i <= 2055u) return 45.3321078265725;
  if (i <= 2267u) return 47.6130234284697;
  if (i <= 2503u) return 50.029991005396;
  if (i <= 2763u) return 52.5642464038057;
  if (i <= 3048u) return 55.208694967369;
  if (i <= 3363u) return 57.9913786695919;
  if (i <= 3708u) return 60.8933493905533;
  if (i <= 4092u) return 63.9687423668779;
  if (i <= 4512u) return 67.1714224949867;
  if (i <= 4980u) return 70.5691150575094;
  if (i <= 5491u) return 74.1012820401914;
  if (i <= 6058u) return 77.8331548891602;
  if (i <= 6681u) return 81.7373843476778;
  if (i <= 7369u) return 85.842879728024;
  if (i <= 8129u) return 90.160967164289;
  if (i <= 8966u) return 94.6889645101265;
  if (i <= 9893u) return 99.4635611668917;
  if (i <= 10910u) return 104.450945424156;
  if (i <= 12030u) return 109.68135666557;
  if (i <= 13270u) return 115.195486022674;
  if (i <= 14634u) return 120.971070921936;
  if (i <= 16134u) return 127.019683514013;
  if (i <= 17790u) return 133.379158791769;
  if (i <= 19623u) return 140.08211877324;
  if (i <= 21639u) return 147.102005424807;
  if (i <= 23865u) return 154.483008774428;
  if (i <= 26325u) return 162.24980739588;
  if (i <= 29029u) return 170.378989314997;
  if (i <= 32021u) return 178.94412535761;
  if (i <= 35319u) return 187.933498876597;
  if (i <= 38955u) return 197.370210518204;
  if (i <= 42964u) return 207.277591649459;
  if (i <= 47384u) return 217.678662252413;
  if (i <= 52256u) return 228.595712995673;
  if (i <= 57624u) return 240.049994792751;
  if (i <= 63552u) return 252.09522010542;
  if (i <= 70077u) return 264.720607433573;
  if (i <= 77279u) return 277.991007048789;
  if (i <= 85217u) return 291.919509454233;
  if (i <= 93975u) return 306.553421119387;
  if (i <= 103635u) return 321.923904051874;
  if (i <= 114259u) return 338.022188620806;
  if (i <= 125974u) return 354.928161745444;
  if (i <= 138889u) return 372.678145321134;
  if (i <= 153134u) return 391.323395671662;
  if (i <= 168851u) return 410.914833025044;
  if (i <= 186194u) return 431.5020278052;
  if (i <= 205286u) return 453.084980991425;
  if (i <= 226346u) return 475.758342018298;
  if (i <= 249564u) return 499.563809738055;
  if (i <= 275191u) return 524.586503829445;
  if (i <= 303427u) return 550.842082633489;
  if (i <= 334557u) return 578.409024825858;
  if (i <= 368871u) return 607.347511726195;
  if (i <= 406731u) return 637.754655020251;
  if (i <= 448437u) return 669.654388472143;
  if (i <= 494439u) return 703.163565609027;
  if (i <= 545119u) return 738.321745582507;
  if (i <= 601037u) return 775.265760884614;
  if (i <= 662714u) return 814.072478345755;
  if (i <= 730673u) return 854.794127261062;
  if (i <= 805643u) return 897.576180610872;
  if (i <= 888235u) return 942.46220083354;
  if (i <= 979321u) return 989.60648744842;
  if (i <= 1079771u) return 1039.1203010239;
  if (i <= 1190496u) return 1091.09852900643;
  if (i <= 1312576u) return 1145.67709237813;
  if (i <= 1447210u) return 1203.00041562753;
  if (i <= 1595650u) return 1263.19040528338;
  if (i <= 1759324u) return 1326.3951145869;
  if (i <= 1939768u) return 1392.75554208195;
  if (i <= 2138677u) return 1462.42162183141;
  if (i <= 2357969u) return 1535.5679730966;
  if (i <= 2599709u) return 1612.3613118653;
  if (i <= 2866325u) return 1693.02244521448;
  if (i <= 3160216u) return 1777.69963717159;
  if (i <= 3484303u) return 1866.62877937741;
  if (i <= 3841609u) return 1960.00229591702;
  if (i <= 4235569u) return 2058.04980503388;
  if (i <= 4669759u) return 2160.962517028;
  if (i <= 5148415u) return 2269.011899484;
  if (i <= 5676351u) return 2382.50939137708;
  if (i <= 6258261u) return 2501.65165440754;
  if (i <= 6899761u) return 2626.73961404628;
  if (i <= 7607161u) return 2758.10822847835;
  if (i <= 8387061u) return 2896.04229941484;
  if (i <= 9246836u) return 3040.86106226509;
  if (i <= 10194708u) return 3192.91528230863;
  if (i <= 11239752u) return 3352.57393654487;
  if (i <= 12392152u) return 3520.24885483967;
  if (i <= 13662520u) return 3696.2846210756;
  if (i <= 15063244u) return 3881.13952338743;
  if (i <= 16607484u) return 4075.22809177597;
  if (i <= 18309965u) return 4279.01448934214;
  if (i <= 20187057u) return 4493.00089027367;
  if (i <= 22256498u) return 4717.67930236891;
  if (i <= 24538022u) return 4953.58678131311;
  if (i <= 27053612u) return 5201.30868147623;
  if (i <= 29826772u) return 5461.3892005606;
  if (i <= 32884372u) return 5734.48968958878;
  if (i <= 36255331u) return 6021.23998857378;
  if (i <= 39972079u) return 6322.34758614235;
  if (i <= 44069335u) return 6638.47384569677;
  if (i <= 48587017u) return 6970.43879537006;
  if (i <= 53567779u) return 7319.00122967608;
  if (i <= 59059051u) return 7684.98867923694;
  if (i <= 65113195u) return 8069.27475055844;
  if (i <= 71787681u) return 8472.76112020161;
  if (i <= 79146417u) return 8896.4272042208;
  if (i <= 87259431u) return 9341.27566234934;
  if (i <= 96204349u) return 9808.38156884203;
  if (i <= 106066089u) return 10298.8392064349;
  if (i <= 116938503u) return 10813.8107529215;
  if (i <= 128925712u) return 11354.5458737899;
  if (i <= 142141652u) return 11922.3173921851;
  if (i <= 156711468u) return 12518.445111115;
  if (i <= 172775559u) return 13144.4117023167;
  if (i <= 190485651u) return 13801.6539226283;
  if (i <= 210011271u) return 14491.7656274175;
  if (i <= 231537615u) return 15216.360110092;
  if (i <= 255271299u) return 15977.2118656542;
  if (i <= 281438144u) return 16776.1182637701;
  if (i <= 310285898u) return 17614.9339482156;
  if (i <= 342091319u) return 18495.710827108;
  if (i <= 377155755u) return 19420.4983200741;
  if (i <= 415815149u) return 20391.5460178967;
  if (i <= 458436366u) return 21411.1271538889;
  if (i <= 505427034u) return 22481.7044282679;
  if (i <= 557234442u) return 23605.8137330616;
  if (i <= 614351162u) return 24786.1082463544;
  if (i <= 677324576u) return 26025.4601496304;
  if (i <= 746751140u) return 27326.7477025716;
  if (i <= 823293584u) return 28693.0929667751;
  if (i <= 907682350u) return 30127.7670928331;
  if (i <= 1000720018u) return 31634.1590373444;
  if (i <= 1103296108u) return 33215.9014328981;
  if (i <= 1216386121u) return 34876.7274984337;
  if (i <= 1341067293u) return 36620.5856452351;
  if (i <= 1478527787u) return 38451.6291852504;
  if (i <= 1630078462u) return 40374.2301722274;
  if (i <= 1797161818u) return 42392.9453800983;
  if (i <= 1981371802u) return 44512.60273226;
  if (i <= 2184466481u) return 46738.2764016817;
  if (i <= 2408377949u) return 49075.2274472569;
  if (i <= 2655239305u) return 51529.014205591;
  if (i <= 2927404009u) return 54105.4896382983;
  if (i <= 3227464249u) return 56810.7758176211;
  if (i <= 3558280241u) return 59651.3222066368;
  return 65535.9999923706;
}
