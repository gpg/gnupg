/* tiger.c  -  The TIGER hash function
 *	Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "memory.h"
#include "algorithms.h"

#ifdef HAVE_U64_TYPEDEF

/* we really need it here, but as this is only experiment we
 * can live without Tiger */

typedef struct {
    u64  a, b, c;
    byte buf[64];
    int  count;
    u32  nblocks;
} TIGER_CONTEXT;


/*********************************
 * Okay, okay, this is not the fastest code - improvements are welcome.
 *
 */

/* Some test vectors:
 * ""                   24F0130C63AC9332 16166E76B1BB925F F373DE2D49584E7A
 * "abc"                F258C1E88414AB2A 527AB541FFC5B8BF 935F7B951C132951
 * "Tiger"              9F00F599072300DD 276ABB38C8EB6DEC 37790C116F9D2BDF
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
 *			87FB2A9083851CF7 470D2CF810E6DF9E B586445034A5A386
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789"
 *			467DB80863EBCE48 8DF1CD1261655DE9 57896565975F9197
 * "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham"
 *			0C410A042968868A 1671DA5A3FD29A72 5EC1E457D3CDB303
 * "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proc"
 * "eedings of Fast Software Encryption 3, Cambridge."
 *			EBF591D5AFA655CE 7F22894FF87F54AC 89C811B6B0DA3193
 * "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proc"
 * "eedings of Fast Software Encryption 3, Cambridge, 1996."
 *			3D9AEB03D1BD1A63 57B2774DFD6D5B24 DD68151D503974FC
 * "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEF"
 * "GHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
 *			00B83EB4E53440C5 76AC6AAEE0A74858 25FD15E70A59FFE4
 */


static u64 sbox1[256] = {
    0x02aab17cf7e90c5eLL /*    0 */,	0xac424b03e243a8ecLL /*    1 */,
    0x72cd5be30dd5fcd3LL /*    2 */,	0x6d019b93f6f97f3aLL /*    3 */,
    0xcd9978ffd21f9193LL /*    4 */,	0x7573a1c9708029e2LL /*    5 */,
    0xb164326b922a83c3LL /*    6 */,	0x46883eee04915870LL /*    7 */,
    0xeaace3057103ece6LL /*    8 */,	0xc54169b808a3535cLL /*    9 */,
    0x4ce754918ddec47cLL /*   10 */,	0x0aa2f4dfdc0df40cLL /*   11 */,
    0x10b76f18a74dbefaLL /*   12 */,	0xc6ccb6235ad1ab6aLL /*   13 */,
    0x13726121572fe2ffLL /*   14 */,	0x1a488c6f199d921eLL /*   15 */,
    0x4bc9f9f4da0007caLL /*   16 */,	0x26f5e6f6e85241c7LL /*   17 */,
    0x859079dbea5947b6LL /*   18 */,	0x4f1885c5c99e8c92LL /*   19 */,
    0xd78e761ea96f864bLL /*   20 */,	0x8e36428c52b5c17dLL /*   21 */,
    0x69cf6827373063c1LL /*   22 */,	0xb607c93d9bb4c56eLL /*   23 */,
    0x7d820e760e76b5eaLL /*   24 */,	0x645c9cc6f07fdc42LL /*   25 */,
    0xbf38a078243342e0LL /*   26 */,	0x5f6b343c9d2e7d04LL /*   27 */,
    0xf2c28aeb600b0ec6LL /*   28 */,	0x6c0ed85f7254bcacLL /*   29 */,
    0x71592281a4db4fe5LL /*   30 */,	0x1967fa69ce0fed9fLL /*   31 */,
    0xfd5293f8b96545dbLL /*   32 */,	0xc879e9d7f2a7600bLL /*   33 */,
    0x860248920193194eLL /*   34 */,	0xa4f9533b2d9cc0b3LL /*   35 */,
    0x9053836c15957613LL /*   36 */,	0xdb6dcf8afc357bf1LL /*   37 */,
    0x18beea7a7a370f57LL /*   38 */,	0x037117ca50b99066LL /*   39 */,
    0x6ab30a9774424a35LL /*   40 */,	0xf4e92f02e325249bLL /*   41 */,
    0x7739db07061ccae1LL /*   42 */,	0xd8f3b49ceca42a05LL /*   43 */,
    0xbd56be3f51382f73LL /*   44 */,	0x45faed5843b0bb28LL /*   45 */,
    0x1c813d5c11bf1f83LL /*   46 */,	0x8af0e4b6d75fa169LL /*   47 */,
    0x33ee18a487ad9999LL /*   48 */,	0x3c26e8eab1c94410LL /*   49 */,
    0xb510102bc0a822f9LL /*   50 */,	0x141eef310ce6123bLL /*   51 */,
    0xfc65b90059ddb154LL /*   52 */,	0xe0158640c5e0e607LL /*   53 */,
    0x884e079826c3a3cfLL /*   54 */,	0x930d0d9523c535fdLL /*   55 */,
    0x35638d754e9a2b00LL /*   56 */,	0x4085fccf40469dd5LL /*   57 */,
    0xc4b17ad28be23a4cLL /*   58 */,	0xcab2f0fc6a3e6a2eLL /*   59 */,
    0x2860971a6b943fcdLL /*   60 */,	0x3dde6ee212e30446LL /*   61 */,
    0x6222f32ae01765aeLL /*   62 */,	0x5d550bb5478308feLL /*   63 */,
    0xa9efa98da0eda22aLL /*   64 */,	0xc351a71686c40da7LL /*   65 */,
    0x1105586d9c867c84LL /*   66 */,	0xdcffee85fda22853LL /*   67 */,
    0xccfbd0262c5eef76LL /*   68 */,	0xbaf294cb8990d201LL /*   69 */,
    0xe69464f52afad975LL /*   70 */,	0x94b013afdf133e14LL /*   71 */,
    0x06a7d1a32823c958LL /*   72 */,	0x6f95fe5130f61119LL /*   73 */,
    0xd92ab34e462c06c0LL /*   74 */,	0xed7bde33887c71d2LL /*   75 */,
    0x79746d6e6518393eLL /*   76 */,	0x5ba419385d713329LL /*   77 */,
    0x7c1ba6b948a97564LL /*   78 */,	0x31987c197bfdac67LL /*   79 */,
    0xde6c23c44b053d02LL /*   80 */,	0x581c49fed002d64dLL /*   81 */,
    0xdd474d6338261571LL /*   82 */,	0xaa4546c3e473d062LL /*   83 */,
    0x928fce349455f860LL /*   84 */,	0x48161bbacaab94d9LL /*   85 */,
    0x63912430770e6f68LL /*   86 */,	0x6ec8a5e602c6641cLL /*   87 */,
    0x87282515337ddd2bLL /*   88 */,	0x2cda6b42034b701bLL /*   89 */,
    0xb03d37c181cb096dLL /*   90 */,	0xe108438266c71c6fLL /*   91 */,
    0x2b3180c7eb51b255LL /*   92 */,	0xdf92b82f96c08bbcLL /*   93 */,
    0x5c68c8c0a632f3baLL /*   94 */,	0x5504cc861c3d0556LL /*   95 */,
    0xabbfa4e55fb26b8fLL /*   96 */,	0x41848b0ab3baceb4LL /*   97 */,
    0xb334a273aa445d32LL /*   98 */,	0xbca696f0a85ad881LL /*   99 */,
    0x24f6ec65b528d56cLL /*  100 */,	0x0ce1512e90f4524aLL /*  101 */,
    0x4e9dd79d5506d35aLL /*  102 */,	0x258905fac6ce9779LL /*  103 */,
    0x2019295b3e109b33LL /*  104 */,	0xf8a9478b73a054ccLL /*  105 */,
    0x2924f2f934417eb0LL /*  106 */,	0x3993357d536d1bc4LL /*  107 */,
    0x38a81ac21db6ff8bLL /*  108 */,	0x47c4fbf17d6016bfLL /*  109 */,
    0x1e0faadd7667e3f5LL /*  110 */,	0x7abcff62938beb96LL /*  111 */,
    0xa78dad948fc179c9LL /*  112 */,	0x8f1f98b72911e50dLL /*  113 */,
    0x61e48eae27121a91LL /*  114 */,	0x4d62f7ad31859808LL /*  115 */,
    0xeceba345ef5ceaebLL /*  116 */,	0xf5ceb25ebc9684ceLL /*  117 */,
    0xf633e20cb7f76221LL /*  118 */,	0xa32cdf06ab8293e4LL /*  119 */,
    0x985a202ca5ee2ca4LL /*  120 */,	0xcf0b8447cc8a8fb1LL /*  121 */,
    0x9f765244979859a3LL /*  122 */,	0xa8d516b1a1240017LL /*  123 */,
    0x0bd7ba3ebb5dc726LL /*  124 */,	0xe54bca55b86adb39LL /*  125 */,
    0x1d7a3afd6c478063LL /*  126 */,	0x519ec608e7669eddLL /*  127 */,
    0x0e5715a2d149aa23LL /*  128 */,	0x177d4571848ff194LL /*  129 */,
    0xeeb55f3241014c22LL /*  130 */,	0x0f5e5ca13a6e2ec2LL /*  131 */,
    0x8029927b75f5c361LL /*  132 */,	0xad139fabc3d6e436LL /*  133 */,
    0x0d5df1a94ccf402fLL /*  134 */,	0x3e8bd948bea5dfc8LL /*  135 */,
    0xa5a0d357bd3ff77eLL /*  136 */,	0xa2d12e251f74f645LL /*  137 */,
    0x66fd9e525e81a082LL /*  138 */,	0x2e0c90ce7f687a49LL /*  139 */,
    0xc2e8bcbeba973bc5LL /*  140 */,	0x000001bce509745fLL /*  141 */,
    0x423777bbe6dab3d6LL /*  142 */,	0xd1661c7eaef06eb5LL /*  143 */,
    0xa1781f354daacfd8LL /*  144 */,	0x2d11284a2b16affcLL /*  145 */,
    0xf1fc4f67fa891d1fLL /*  146 */,	0x73ecc25dcb920adaLL /*  147 */,
    0xae610c22c2a12651LL /*  148 */,	0x96e0a810d356b78aLL /*  149 */,
    0x5a9a381f2fe7870fLL /*  150 */,	0xd5ad62ede94e5530LL /*  151 */,
    0xd225e5e8368d1427LL /*  152 */,	0x65977b70c7af4631LL /*  153 */,
    0x99f889b2de39d74fLL /*  154 */,	0x233f30bf54e1d143LL /*  155 */,
    0x9a9675d3d9a63c97LL /*  156 */,	0x5470554ff334f9a8LL /*  157 */,
    0x166acb744a4f5688LL /*  158 */,	0x70c74caab2e4aeadLL /*  159 */,
    0xf0d091646f294d12LL /*  160 */,	0x57b82a89684031d1LL /*  161 */,
    0xefd95a5a61be0b6bLL /*  162 */,	0x2fbd12e969f2f29aLL /*  163 */,
    0x9bd37013feff9fe8LL /*  164 */,	0x3f9b0404d6085a06LL /*  165 */,
    0x4940c1f3166cfe15LL /*  166 */,	0x09542c4dcdf3defbLL /*  167 */,
    0xb4c5218385cd5ce3LL /*  168 */,	0xc935b7dc4462a641LL /*  169 */,
    0x3417f8a68ed3b63fLL /*  170 */,	0xb80959295b215b40LL /*  171 */,
    0xf99cdaef3b8c8572LL /*  172 */,	0x018c0614f8fcb95dLL /*  173 */,
    0x1b14accd1a3acdf3LL /*  174 */,	0x84d471f200bb732dLL /*  175 */,
    0xc1a3110e95e8da16LL /*  176 */,	0x430a7220bf1a82b8LL /*  177 */,
    0xb77e090d39df210eLL /*  178 */,	0x5ef4bd9f3cd05e9dLL /*  179 */,
    0x9d4ff6da7e57a444LL /*  180 */,	0xda1d60e183d4a5f8LL /*  181 */,
    0xb287c38417998e47LL /*  182 */,	0xfe3edc121bb31886LL /*  183 */,
    0xc7fe3ccc980ccbefLL /*  184 */,	0xe46fb590189bfd03LL /*  185 */,
    0x3732fd469a4c57dcLL /*  186 */,	0x7ef700a07cf1ad65LL /*  187 */,
    0x59c64468a31d8859LL /*  188 */,	0x762fb0b4d45b61f6LL /*  189 */,
    0x155baed099047718LL /*  190 */,	0x68755e4c3d50baa6LL /*  191 */,
    0xe9214e7f22d8b4dfLL /*  192 */,	0x2addbf532eac95f4LL /*  193 */,
    0x32ae3909b4bd0109LL /*  194 */,	0x834df537b08e3450LL /*  195 */,
    0xfa209da84220728dLL /*  196 */,	0x9e691d9b9efe23f7LL /*  197 */,
    0x0446d288c4ae8d7fLL /*  198 */,	0x7b4cc524e169785bLL /*  199 */,
    0x21d87f0135ca1385LL /*  200 */,	0xcebb400f137b8aa5LL /*  201 */,
    0x272e2b66580796beLL /*  202 */,	0x3612264125c2b0deLL /*  203 */,
    0x057702bdad1efbb2LL /*  204 */,	0xd4babb8eacf84be9LL /*  205 */,
    0x91583139641bc67bLL /*  206 */,	0x8bdc2de08036e024LL /*  207 */,
    0x603c8156f49f68edLL /*  208 */,	0xf7d236f7dbef5111LL /*  209 */,
    0x9727c4598ad21e80LL /*  210 */,	0xa08a0896670a5fd7LL /*  211 */,
    0xcb4a8f4309eba9cbLL /*  212 */,	0x81af564b0f7036a1LL /*  213 */,
    0xc0b99aa778199abdLL /*  214 */,	0x959f1ec83fc8e952LL /*  215 */,
    0x8c505077794a81b9LL /*  216 */,	0x3acaaf8f056338f0LL /*  217 */,
    0x07b43f50627a6778LL /*  218 */,	0x4a44ab49f5eccc77LL /*  219 */,
    0x3bc3d6e4b679ee98LL /*  220 */,	0x9cc0d4d1cf14108cLL /*  221 */,
    0x4406c00b206bc8a0LL /*  222 */,	0x82a18854c8d72d89LL /*  223 */,
    0x67e366b35c3c432cLL /*  224 */,	0xb923dd61102b37f2LL /*  225 */,
    0x56ab2779d884271dLL /*  226 */,	0xbe83e1b0ff1525afLL /*  227 */,
    0xfb7c65d4217e49a9LL /*  228 */,	0x6bdbe0e76d48e7d4LL /*  229 */,
    0x08df828745d9179eLL /*  230 */,	0x22ea6a9add53bd34LL /*  231 */,
    0xe36e141c5622200aLL /*  232 */,	0x7f805d1b8cb750eeLL /*  233 */,
    0xafe5c7a59f58e837LL /*  234 */,	0xe27f996a4fb1c23cLL /*  235 */,
    0xd3867dfb0775f0d0LL /*  236 */,	0xd0e673de6e88891aLL /*  237 */,
    0x123aeb9eafb86c25LL /*  238 */,	0x30f1d5d5c145b895LL /*  239 */,
    0xbb434a2dee7269e7LL /*  240 */,	0x78cb67ecf931fa38LL /*  241 */,
    0xf33b0372323bbf9cLL /*  242 */,	0x52d66336fb279c74LL /*  243 */,
    0x505f33ac0afb4eaaLL /*  244 */,	0xe8a5cd99a2cce187LL /*  245 */,
    0x534974801e2d30bbLL /*  246 */,	0x8d2d5711d5876d90LL /*  247 */,
    0x1f1a412891bc038eLL /*  248 */,	0xd6e2e71d82e56648LL /*  249 */,
    0x74036c3a497732b7LL /*  250 */,	0x89b67ed96361f5abLL /*  251 */,
    0xffed95d8f1ea02a2LL /*  252 */,	0xe72b3bd61464d43dLL /*  253 */,
    0xa6300f170bdc4820LL /*  254 */,	0xebc18760ed78a77aLL /*  255 */
};
static u64 sbox2[256] = {
    0xe6a6be5a05a12138LL /*  256 */,	0xb5a122a5b4f87c98LL /*  257 */,
    0x563c6089140b6990LL /*  258 */,	0x4c46cb2e391f5dd5LL /*  259 */,
    0xd932addbc9b79434LL /*  260 */,	0x08ea70e42015aff5LL /*  261 */,
    0xd765a6673e478cf1LL /*  262 */,	0xc4fb757eab278d99LL /*  263 */,
    0xdf11c6862d6e0692LL /*  264 */,	0xddeb84f10d7f3b16LL /*  265 */,
    0x6f2ef604a665ea04LL /*  266 */,	0x4a8e0f0ff0e0dfb3LL /*  267 */,
    0xa5edeef83dbcba51LL /*  268 */,	0xfc4f0a2a0ea4371eLL /*  269 */,
    0xe83e1da85cb38429LL /*  270 */,	0xdc8ff882ba1b1ce2LL /*  271 */,
    0xcd45505e8353e80dLL /*  272 */,	0x18d19a00d4db0717LL /*  273 */,
    0x34a0cfeda5f38101LL /*  274 */,	0x0be77e518887caf2LL /*  275 */,
    0x1e341438b3c45136LL /*  276 */,	0xe05797f49089ccf9LL /*  277 */,
    0xffd23f9df2591d14LL /*  278 */,	0x543dda228595c5cdLL /*  279 */,
    0x661f81fd99052a33LL /*  280 */,	0x8736e641db0f7b76LL /*  281 */,
    0x15227725418e5307LL /*  282 */,	0xe25f7f46162eb2faLL /*  283 */,
    0x48a8b2126c13d9feLL /*  284 */,	0xafdc541792e76eeaLL /*  285 */,
    0x03d912bfc6d1898fLL /*  286 */,	0x31b1aafa1b83f51bLL /*  287 */,
    0xf1ac2796e42ab7d9LL /*  288 */,	0x40a3a7d7fcd2ebacLL /*  289 */,
    0x1056136d0afbbcc5LL /*  290 */,	0x7889e1dd9a6d0c85LL /*  291 */,
    0xd33525782a7974aaLL /*  292 */,	0xa7e25d09078ac09bLL /*  293 */,
    0xbd4138b3eac6edd0LL /*  294 */,	0x920abfbe71eb9e70LL /*  295 */,
    0xa2a5d0f54fc2625cLL /*  296 */,	0xc054e36b0b1290a3LL /*  297 */,
    0xf6dd59ff62fe932bLL /*  298 */,	0x3537354511a8ac7dLL /*  299 */,
    0xca845e9172fadcd4LL /*  300 */,	0x84f82b60329d20dcLL /*  301 */,
    0x79c62ce1cd672f18LL /*  302 */,	0x8b09a2add124642cLL /*  303 */,
    0xd0c1e96a19d9e726LL /*  304 */,	0x5a786a9b4ba9500cLL /*  305 */,
    0x0e020336634c43f3LL /*  306 */,	0xc17b474aeb66d822LL /*  307 */,
    0x6a731ae3ec9baac2LL /*  308 */,	0x8226667ae0840258LL /*  309 */,
    0x67d4567691caeca5LL /*  310 */,	0x1d94155c4875adb5LL /*  311 */,
    0x6d00fd985b813fdfLL /*  312 */,	0x51286efcb774cd06LL /*  313 */,
    0x5e8834471fa744afLL /*  314 */,	0xf72ca0aee761ae2eLL /*  315 */,
    0xbe40e4cdaee8e09aLL /*  316 */,	0xe9970bbb5118f665LL /*  317 */,
    0x726e4beb33df1964LL /*  318 */,	0x703b000729199762LL /*  319 */,
    0x4631d816f5ef30a7LL /*  320 */,	0xb880b5b51504a6beLL /*  321 */,
    0x641793c37ed84b6cLL /*  322 */,	0x7b21ed77f6e97d96LL /*  323 */,
    0x776306312ef96b73LL /*  324 */,	0xae528948e86ff3f4LL /*  325 */,
    0x53dbd7f286a3f8f8LL /*  326 */,	0x16cadce74cfc1063LL /*  327 */,
    0x005c19bdfa52c6ddLL /*  328 */,	0x68868f5d64d46ad3LL /*  329 */,
    0x3a9d512ccf1e186aLL /*  330 */,	0x367e62c2385660aeLL /*  331 */,
    0xe359e7ea77dcb1d7LL /*  332 */,	0x526c0773749abe6eLL /*  333 */,
    0x735ae5f9d09f734bLL /*  334 */,	0x493fc7cc8a558ba8LL /*  335 */,
    0xb0b9c1533041ab45LL /*  336 */,	0x321958ba470a59bdLL /*  337 */,
    0x852db00b5f46c393LL /*  338 */,	0x91209b2bd336b0e5LL /*  339 */,
    0x6e604f7d659ef19fLL /*  340 */,	0xb99a8ae2782ccb24LL /*  341 */,
    0xccf52ab6c814c4c7LL /*  342 */,	0x4727d9afbe11727bLL /*  343 */,
    0x7e950d0c0121b34dLL /*  344 */,	0x756f435670ad471fLL /*  345 */,
    0xf5add442615a6849LL /*  346 */,	0x4e87e09980b9957aLL /*  347 */,
    0x2acfa1df50aee355LL /*  348 */,	0xd898263afd2fd556LL /*  349 */,
    0xc8f4924dd80c8fd6LL /*  350 */,	0xcf99ca3d754a173aLL /*  351 */,
    0xfe477bacaf91bf3cLL /*  352 */,	0xed5371f6d690c12dLL /*  353 */,
    0x831a5c285e687094LL /*  354 */,	0xc5d3c90a3708a0a4LL /*  355 */,
    0x0f7f903717d06580LL /*  356 */,	0x19f9bb13b8fdf27fLL /*  357 */,
    0xb1bd6f1b4d502843LL /*  358 */,	0x1c761ba38fff4012LL /*  359 */,
    0x0d1530c4e2e21f3bLL /*  360 */,	0x8943ce69a7372c8aLL /*  361 */,
    0xe5184e11feb5ce66LL /*  362 */,	0x618bdb80bd736621LL /*  363 */,
    0x7d29bad68b574d0bLL /*  364 */,	0x81bb613e25e6fe5bLL /*  365 */,
    0x071c9c10bc07913fLL /*  366 */,	0xc7beeb7909ac2d97LL /*  367 */,
    0xc3e58d353bc5d757LL /*  368 */,	0xeb017892f38f61e8LL /*  369 */,
    0xd4effb9c9b1cc21aLL /*  370 */,	0x99727d26f494f7abLL /*  371 */,
    0xa3e063a2956b3e03LL /*  372 */,	0x9d4a8b9a4aa09c30LL /*  373 */,
    0x3f6ab7d500090fb4LL /*  374 */,	0x9cc0f2a057268ac0LL /*  375 */,
    0x3dee9d2dedbf42d1LL /*  376 */,	0x330f49c87960a972LL /*  377 */,
    0xc6b2720287421b41LL /*  378 */,	0x0ac59ec07c00369cLL /*  379 */,
    0xef4eac49cb353425LL /*  380 */,	0xf450244eef0129d8LL /*  381 */,
    0x8acc46e5caf4deb6LL /*  382 */,	0x2ffeab63989263f7LL /*  383 */,
    0x8f7cb9fe5d7a4578LL /*  384 */,	0x5bd8f7644e634635LL /*  385 */,
    0x427a7315bf2dc900LL /*  386 */,	0x17d0c4aa2125261cLL /*  387 */,
    0x3992486c93518e50LL /*  388 */,	0xb4cbfee0a2d7d4c3LL /*  389 */,
    0x7c75d6202c5ddd8dLL /*  390 */,	0xdbc295d8e35b6c61LL /*  391 */,
    0x60b369d302032b19LL /*  392 */,	0xce42685fdce44132LL /*  393 */,
    0x06f3ddb9ddf65610LL /*  394 */,	0x8ea4d21db5e148f0LL /*  395 */,
    0x20b0fce62fcd496fLL /*  396 */,	0x2c1b912358b0ee31LL /*  397 */,
    0xb28317b818f5a308LL /*  398 */,	0xa89c1e189ca6d2cfLL /*  399 */,
    0x0c6b18576aaadbc8LL /*  400 */,	0xb65deaa91299fae3LL /*  401 */,
    0xfb2b794b7f1027e7LL /*  402 */,	0x04e4317f443b5bebLL /*  403 */,
    0x4b852d325939d0a6LL /*  404 */,	0xd5ae6beefb207ffcLL /*  405 */,
    0x309682b281c7d374LL /*  406 */,	0xbae309a194c3b475LL /*  407 */,
    0x8cc3f97b13b49f05LL /*  408 */,	0x98a9422ff8293967LL /*  409 */,
    0x244b16b01076ff7cLL /*  410 */,	0xf8bf571c663d67eeLL /*  411 */,
    0x1f0d6758eee30da1LL /*  412 */,	0xc9b611d97adeb9b7LL /*  413 */,
    0xb7afd5887b6c57a2LL /*  414 */,	0x6290ae846b984fe1LL /*  415 */,
    0x94df4cdeacc1a5fdLL /*  416 */,	0x058a5bd1c5483affLL /*  417 */,
    0x63166cc142ba3c37LL /*  418 */,	0x8db8526eb2f76f40LL /*  419 */,
    0xe10880036f0d6d4eLL /*  420 */,	0x9e0523c9971d311dLL /*  421 */,
    0x45ec2824cc7cd691LL /*  422 */,	0x575b8359e62382c9LL /*  423 */,
    0xfa9e400dc4889995LL /*  424 */,	0xd1823ecb45721568LL /*  425 */,
    0xdafd983b8206082fLL /*  426 */,	0xaa7d29082386a8cbLL /*  427 */,
    0x269fcd4403b87588LL /*  428 */,	0x1b91f5f728bdd1e0LL /*  429 */,
    0xe4669f39040201f6LL /*  430 */,	0x7a1d7c218cf04adeLL /*  431 */,
    0x65623c29d79ce5ceLL /*  432 */,	0x2368449096c00bb1LL /*  433 */,
    0xab9bf1879da503baLL /*  434 */,	0xbc23ecb1a458058eLL /*  435 */,
    0x9a58df01bb401eccLL /*  436 */,	0xa070e868a85f143dLL /*  437 */,
    0x4ff188307df2239eLL /*  438 */,	0x14d565b41a641183LL /*  439 */,
    0xee13337452701602LL /*  440 */,	0x950e3dcf3f285e09LL /*  441 */,
    0x59930254b9c80953LL /*  442 */,	0x3bf299408930da6dLL /*  443 */,
    0xa955943f53691387LL /*  444 */,	0xa15edecaa9cb8784LL /*  445 */,
    0x29142127352be9a0LL /*  446 */,	0x76f0371fff4e7afbLL /*  447 */,
    0x0239f450274f2228LL /*  448 */,	0xbb073af01d5e868bLL /*  449 */,
    0xbfc80571c10e96c1LL /*  450 */,	0xd267088568222e23LL /*  451 */,
    0x9671a3d48e80b5b0LL /*  452 */,	0x55b5d38ae193bb81LL /*  453 */,
    0x693ae2d0a18b04b8LL /*  454 */,	0x5c48b4ecadd5335fLL /*  455 */,
    0xfd743b194916a1caLL /*  456 */,	0x2577018134be98c4LL /*  457 */,
    0xe77987e83c54a4adLL /*  458 */,	0x28e11014da33e1b9LL /*  459 */,
    0x270cc59e226aa213LL /*  460 */,	0x71495f756d1a5f60LL /*  461 */,
    0x9be853fb60afef77LL /*  462 */,	0xadc786a7f7443dbfLL /*  463 */,
    0x0904456173b29a82LL /*  464 */,	0x58bc7a66c232bd5eLL /*  465 */,
    0xf306558c673ac8b2LL /*  466 */,	0x41f639c6b6c9772aLL /*  467 */,
    0x216defe99fda35daLL /*  468 */,	0x11640cc71c7be615LL /*  469 */,
    0x93c43694565c5527LL /*  470 */,	0xea038e6246777839LL /*  471 */,
    0xf9abf3ce5a3e2469LL /*  472 */,	0x741e768d0fd312d2LL /*  473 */,
    0x0144b883ced652c6LL /*  474 */,	0xc20b5a5ba33f8552LL /*  475 */,
    0x1ae69633c3435a9dLL /*  476 */,	0x97a28ca4088cfdecLL /*  477 */,
    0x8824a43c1e96f420LL /*  478 */,	0x37612fa66eeea746LL /*  479 */,
    0x6b4cb165f9cf0e5aLL /*  480 */,	0x43aa1c06a0abfb4aLL /*  481 */,
    0x7f4dc26ff162796bLL /*  482 */,	0x6cbacc8e54ed9b0fLL /*  483 */,
    0xa6b7ffefd2bb253eLL /*  484 */,	0x2e25bc95b0a29d4fLL /*  485 */,
    0x86d6a58bdef1388cLL /*  486 */,	0xded74ac576b6f054LL /*  487 */,
    0x8030bdbc2b45805dLL /*  488 */,	0x3c81af70e94d9289LL /*  489 */,
    0x3eff6dda9e3100dbLL /*  490 */,	0xb38dc39fdfcc8847LL /*  491 */,
    0x123885528d17b87eLL /*  492 */,	0xf2da0ed240b1b642LL /*  493 */,
    0x44cefadcd54bf9a9LL /*  494 */,	0x1312200e433c7ee6LL /*  495 */,
    0x9ffcc84f3a78c748LL /*  496 */,	0xf0cd1f72248576bbLL /*  497 */,
    0xec6974053638cfe4LL /*  498 */,	0x2ba7b67c0cec4e4cLL /*  499 */,
    0xac2f4df3e5ce32edLL /*  500 */,	0xcb33d14326ea4c11LL /*  501 */,
    0xa4e9044cc77e58bcLL /*  502 */,	0x5f513293d934fcefLL /*  503 */,
    0x5dc9645506e55444LL /*  504 */,	0x50de418f317de40aLL /*  505 */,
    0x388cb31a69dde259LL /*  506 */,	0x2db4a83455820a86LL /*  507 */,
    0x9010a91e84711ae9LL /*  508 */,	0x4df7f0b7b1498371LL /*  509 */,
    0xd62a2eabc0977179LL /*  510 */,	0x22fac097aa8d5c0eLL /*  511 */
};
static u64 sbox3[256] = {
    0xf49fcc2ff1daf39bLL /*  512 */,	0x487fd5c66ff29281LL /*  513 */,
    0xe8a30667fcdca83fLL /*  514 */,	0x2c9b4be3d2fcce63LL /*  515 */,
    0xda3ff74b93fbbbc2LL /*  516 */,	0x2fa165d2fe70ba66LL /*  517 */,
    0xa103e279970e93d4LL /*  518 */,	0xbecdec77b0e45e71LL /*  519 */,
    0xcfb41e723985e497LL /*  520 */,	0xb70aaa025ef75017LL /*  521 */,
    0xd42309f03840b8e0LL /*  522 */,	0x8efc1ad035898579LL /*  523 */,
    0x96c6920be2b2abc5LL /*  524 */,	0x66af4163375a9172LL /*  525 */,
    0x2174abdcca7127fbLL /*  526 */,	0xb33ccea64a72ff41LL /*  527 */,
    0xf04a4933083066a5LL /*  528 */,	0x8d970acdd7289af5LL /*  529 */,
    0x8f96e8e031c8c25eLL /*  530 */,	0xf3fec02276875d47LL /*  531 */,
    0xec7bf310056190ddLL /*  532 */,	0xf5adb0aebb0f1491LL /*  533 */,
    0x9b50f8850fd58892LL /*  534 */,	0x4975488358b74de8LL /*  535 */,
    0xa3354ff691531c61LL /*  536 */,	0x0702bbe481d2c6eeLL /*  537 */,
    0x89fb24057deded98LL /*  538 */,	0xac3075138596e902LL /*  539 */,
    0x1d2d3580172772edLL /*  540 */,	0xeb738fc28e6bc30dLL /*  541 */,
    0x5854ef8f63044326LL /*  542 */,	0x9e5c52325add3bbeLL /*  543 */,
    0x90aa53cf325c4623LL /*  544 */,	0xc1d24d51349dd067LL /*  545 */,
    0x2051cfeea69ea624LL /*  546 */,	0x13220f0a862e7e4fLL /*  547 */,
    0xce39399404e04864LL /*  548 */,	0xd9c42ca47086fcb7LL /*  549 */,
    0x685ad2238a03e7ccLL /*  550 */,	0x066484b2ab2ff1dbLL /*  551 */,
    0xfe9d5d70efbf79ecLL /*  552 */,	0x5b13b9dd9c481854LL /*  553 */,
    0x15f0d475ed1509adLL /*  554 */,	0x0bebcd060ec79851LL /*  555 */,
    0xd58c6791183ab7f8LL /*  556 */,	0xd1187c5052f3eee4LL /*  557 */,
    0xc95d1192e54e82ffLL /*  558 */,	0x86eea14cb9ac6ca2LL /*  559 */,
    0x3485beb153677d5dLL /*  560 */,	0xdd191d781f8c492aLL /*  561 */,
    0xf60866baa784ebf9LL /*  562 */,	0x518f643ba2d08c74LL /*  563 */,
    0x8852e956e1087c22LL /*  564 */,	0xa768cb8dc410ae8dLL /*  565 */,
    0x38047726bfec8e1aLL /*  566 */,	0xa67738b4cd3b45aaLL /*  567 */,
    0xad16691cec0dde19LL /*  568 */,	0xc6d4319380462e07LL /*  569 */,
    0xc5a5876d0ba61938LL /*  570 */,	0x16b9fa1fa58fd840LL /*  571 */,
    0x188ab1173ca74f18LL /*  572 */,	0xabda2f98c99c021fLL /*  573 */,
    0x3e0580ab134ae816LL /*  574 */,	0x5f3b05b773645abbLL /*  575 */,
    0x2501a2be5575f2f6LL /*  576 */,	0x1b2f74004e7e8ba9LL /*  577 */,
    0x1cd7580371e8d953LL /*  578 */,	0x7f6ed89562764e30LL /*  579 */,
    0xb15926ff596f003dLL /*  580 */,	0x9f65293da8c5d6b9LL /*  581 */,
    0x6ecef04dd690f84cLL /*  582 */,	0x4782275fff33af88LL /*  583 */,
    0xe41433083f820801LL /*  584 */,	0xfd0dfe409a1af9b5LL /*  585 */,
    0x4325a3342cdb396bLL /*  586 */,	0x8ae77e62b301b252LL /*  587 */,
    0xc36f9e9f6655615aLL /*  588 */,	0x85455a2d92d32c09LL /*  589 */,
    0xf2c7dea949477485LL /*  590 */,	0x63cfb4c133a39ebaLL /*  591 */,
    0x83b040cc6ebc5462LL /*  592 */,	0x3b9454c8fdb326b0LL /*  593 */,
    0x56f56a9e87ffd78cLL /*  594 */,	0x2dc2940d99f42bc6LL /*  595 */,
    0x98f7df096b096e2dLL /*  596 */,	0x19a6e01e3ad852bfLL /*  597 */,
    0x42a99ccbdbd4b40bLL /*  598 */,	0xa59998af45e9c559LL /*  599 */,
    0x366295e807d93186LL /*  600 */,	0x6b48181bfaa1f773LL /*  601 */,
    0x1fec57e2157a0a1dLL /*  602 */,	0x4667446af6201ad5LL /*  603 */,
    0xe615ebcacfb0f075LL /*  604 */,	0xb8f31f4f68290778LL /*  605 */,
    0x22713ed6ce22d11eLL /*  606 */,	0x3057c1a72ec3c93bLL /*  607 */,
    0xcb46acc37c3f1f2fLL /*  608 */,	0xdbb893fd02aaf50eLL /*  609 */,
    0x331fd92e600b9fcfLL /*  610 */,	0xa498f96148ea3ad6LL /*  611 */,
    0xa8d8426e8b6a83eaLL /*  612 */,	0xa089b274b7735cdcLL /*  613 */,
    0x87f6b3731e524a11LL /*  614 */,	0x118808e5cbc96749LL /*  615 */,
    0x9906e4c7b19bd394LL /*  616 */,	0xafed7f7e9b24a20cLL /*  617 */,
    0x6509eadeeb3644a7LL /*  618 */,	0x6c1ef1d3e8ef0edeLL /*  619 */,
    0xb9c97d43e9798fb4LL /*  620 */,	0xa2f2d784740c28a3LL /*  621 */,
    0x7b8496476197566fLL /*  622 */,	0x7a5be3e6b65f069dLL /*  623 */,
    0xf96330ed78be6f10LL /*  624 */,	0xeee60de77a076a15LL /*  625 */,
    0x2b4bee4aa08b9bd0LL /*  626 */,	0x6a56a63ec7b8894eLL /*  627 */,
    0x02121359ba34fef4LL /*  628 */,	0x4cbf99f8283703fcLL /*  629 */,
    0x398071350caf30c8LL /*  630 */,	0xd0a77a89f017687aLL /*  631 */,
    0xf1c1a9eb9e423569LL /*  632 */,	0x8c7976282dee8199LL /*  633 */,
    0x5d1737a5dd1f7abdLL /*  634 */,	0x4f53433c09a9fa80LL /*  635 */,
    0xfa8b0c53df7ca1d9LL /*  636 */,	0x3fd9dcbc886ccb77LL /*  637 */,
    0xc040917ca91b4720LL /*  638 */,	0x7dd00142f9d1dcdfLL /*  639 */,
    0x8476fc1d4f387b58LL /*  640 */,	0x23f8e7c5f3316503LL /*  641 */,
    0x032a2244e7e37339LL /*  642 */,	0x5c87a5d750f5a74bLL /*  643 */,
    0x082b4cc43698992eLL /*  644 */,	0xdf917becb858f63cLL /*  645 */,
    0x3270b8fc5bf86ddaLL /*  646 */,	0x10ae72bb29b5dd76LL /*  647 */,
    0x576ac94e7700362bLL /*  648 */,	0x1ad112dac61efb8fLL /*  649 */,
    0x691bc30ec5faa427LL /*  650 */,	0xff246311cc327143LL /*  651 */,
    0x3142368e30e53206LL /*  652 */,	0x71380e31e02ca396LL /*  653 */,
    0x958d5c960aad76f1LL /*  654 */,	0xf8d6f430c16da536LL /*  655 */,
    0xc8ffd13f1be7e1d2LL /*  656 */,	0x7578ae66004ddbe1LL /*  657 */,
    0x05833f01067be646LL /*  658 */,	0xbb34b5ad3bfe586dLL /*  659 */,
    0x095f34c9a12b97f0LL /*  660 */,	0x247ab64525d60ca8LL /*  661 */,
    0xdcdbc6f3017477d1LL /*  662 */,	0x4a2e14d4decad24dLL /*  663 */,
    0xbdb5e6d9be0a1eebLL /*  664 */,	0x2a7e70f7794301abLL /*  665 */,
    0xdef42d8a270540fdLL /*  666 */,	0x01078ec0a34c22c1LL /*  667 */,
    0xe5de511af4c16387LL /*  668 */,	0x7ebb3a52bd9a330aLL /*  669 */,
    0x77697857aa7d6435LL /*  670 */,	0x004e831603ae4c32LL /*  671 */,
    0xe7a21020ad78e312LL /*  672 */,	0x9d41a70c6ab420f2LL /*  673 */,
    0x28e06c18ea1141e6LL /*  674 */,	0xd2b28cbd984f6b28LL /*  675 */,
    0x26b75f6c446e9d83LL /*  676 */,	0xba47568c4d418d7fLL /*  677 */,
    0xd80badbfe6183d8eLL /*  678 */,	0x0e206d7f5f166044LL /*  679 */,
    0xe258a43911cbca3eLL /*  680 */,	0x723a1746b21dc0bcLL /*  681 */,
    0xc7caa854f5d7cdd3LL /*  682 */,	0x7cac32883d261d9cLL /*  683 */,
    0x7690c26423ba942cLL /*  684 */,	0x17e55524478042b8LL /*  685 */,
    0xe0be477656a2389fLL /*  686 */,	0x4d289b5e67ab2da0LL /*  687 */,
    0x44862b9c8fbbfd31LL /*  688 */,	0xb47cc8049d141365LL /*  689 */,
    0x822c1b362b91c793LL /*  690 */,	0x4eb14655fb13dfd8LL /*  691 */,
    0x1ecbba0714e2a97bLL /*  692 */,	0x6143459d5cde5f14LL /*  693 */,
    0x53a8fbf1d5f0ac89LL /*  694 */,	0x97ea04d81c5e5b00LL /*  695 */,
    0x622181a8d4fdb3f3LL /*  696 */,	0xe9bcd341572a1208LL /*  697 */,
    0x1411258643cce58aLL /*  698 */,	0x9144c5fea4c6e0a4LL /*  699 */,
    0x0d33d06565cf620fLL /*  700 */,	0x54a48d489f219ca1LL /*  701 */,
    0xc43e5eac6d63c821LL /*  702 */,	0xa9728b3a72770dafLL /*  703 */,
    0xd7934e7b20df87efLL /*  704 */,	0xe35503b61a3e86e5LL /*  705 */,
    0xcae321fbc819d504LL /*  706 */,	0x129a50b3ac60bfa6LL /*  707 */,
    0xcd5e68ea7e9fb6c3LL /*  708 */,	0xb01c90199483b1c7LL /*  709 */,
    0x3de93cd5c295376cLL /*  710 */,	0xaed52edf2ab9ad13LL /*  711 */,
    0x2e60f512c0a07884LL /*  712 */,	0xbc3d86a3e36210c9LL /*  713 */,
    0x35269d9b163951ceLL /*  714 */,	0x0c7d6e2ad0cdb5faLL /*  715 */,
    0x59e86297d87f5733LL /*  716 */,	0x298ef221898db0e7LL /*  717 */,
    0x55000029d1a5aa7eLL /*  718 */,	0x8bc08ae1b5061b45LL /*  719 */,
    0xc2c31c2b6c92703aLL /*  720 */,	0x94cc596baf25ef42LL /*  721 */,
    0x0a1d73db22540456LL /*  722 */,	0x04b6a0f9d9c4179aLL /*  723 */,
    0xeffdafa2ae3d3c60LL /*  724 */,	0xf7c8075bb49496c4LL /*  725 */,
    0x9cc5c7141d1cd4e3LL /*  726 */,	0x78bd1638218e5534LL /*  727 */,
    0xb2f11568f850246aLL /*  728 */,	0xedfabcfa9502bc29LL /*  729 */,
    0x796ce5f2da23051bLL /*  730 */,	0xaae128b0dc93537cLL /*  731 */,
    0x3a493da0ee4b29aeLL /*  732 */,	0xb5df6b2c416895d7LL /*  733 */,
    0xfcabbd25122d7f37LL /*  734 */,	0x70810b58105dc4b1LL /*  735 */,
    0xe10fdd37f7882a90LL /*  736 */,	0x524dcab5518a3f5cLL /*  737 */,
    0x3c9e85878451255bLL /*  738 */,	0x4029828119bd34e2LL /*  739 */,
    0x74a05b6f5d3ceccbLL /*  740 */,	0xb610021542e13ecaLL /*  741 */,
    0x0ff979d12f59e2acLL /*  742 */,	0x6037da27e4f9cc50LL /*  743 */,
    0x5e92975a0df1847dLL /*  744 */,	0xd66de190d3e623feLL /*  745 */,
    0x5032d6b87b568048LL /*  746 */,	0x9a36b7ce8235216eLL /*  747 */,
    0x80272a7a24f64b4aLL /*  748 */,	0x93efed8b8c6916f7LL /*  749 */,
    0x37ddbff44cce1555LL /*  750 */,	0x4b95db5d4b99bd25LL /*  751 */,
    0x92d3fda169812fc0LL /*  752 */,	0xfb1a4a9a90660bb6LL /*  753 */,
    0x730c196946a4b9b2LL /*  754 */,	0x81e289aa7f49da68LL /*  755 */,
    0x64669a0f83b1a05fLL /*  756 */,	0x27b3ff7d9644f48bLL /*  757 */,
    0xcc6b615c8db675b3LL /*  758 */,	0x674f20b9bcebbe95LL /*  759 */,
    0x6f31238275655982LL /*  760 */,	0x5ae488713e45cf05LL /*  761 */,
    0xbf619f9954c21157LL /*  762 */,	0xeabac46040a8eae9LL /*  763 */,
    0x454c6fe9f2c0c1cdLL /*  764 */,	0x419cf6496412691cLL /*  765 */,
    0xd3dc3bef265b0f70LL /*  766 */,	0x6d0e60f5c3578a9eLL /*  767 */
};
static u64 sbox4[256] = {
    0x5b0e608526323c55LL /*  768 */,	0x1a46c1a9fa1b59f5LL /*  769 */,
    0xa9e245a17c4c8ffaLL /*  770 */,	0x65ca5159db2955d7LL /*  771 */,
    0x05db0a76ce35afc2LL /*  772 */,	0x81eac77ea9113d45LL /*  773 */,
    0x528ef88ab6ac0a0dLL /*  774 */,	0xa09ea253597be3ffLL /*  775 */,
    0x430ddfb3ac48cd56LL /*  776 */,	0xc4b3a67af45ce46fLL /*  777 */,
    0x4ececfd8fbe2d05eLL /*  778 */,	0x3ef56f10b39935f0LL /*  779 */,
    0x0b22d6829cd619c6LL /*  780 */,	0x17fd460a74df2069LL /*  781 */,
    0x6cf8cc8e8510ed40LL /*  782 */,	0xd6c824bf3a6ecaa7LL /*  783 */,
    0x61243d581a817049LL /*  784 */,	0x048bacb6bbc163a2LL /*  785 */,
    0xd9a38ac27d44cc32LL /*  786 */,	0x7fddff5baaf410abLL /*  787 */,
    0xad6d495aa804824bLL /*  788 */,	0xe1a6a74f2d8c9f94LL /*  789 */,
    0xd4f7851235dee8e3LL /*  790 */,	0xfd4b7f886540d893LL /*  791 */,
    0x247c20042aa4bfdaLL /*  792 */,	0x096ea1c517d1327cLL /*  793 */,
    0xd56966b4361a6685LL /*  794 */,	0x277da5c31221057dLL /*  795 */,
    0x94d59893a43acff7LL /*  796 */,	0x64f0c51ccdc02281LL /*  797 */,
    0x3d33bcc4ff6189dbLL /*  798 */,	0xe005cb184ce66af1LL /*  799 */,
    0xff5ccd1d1db99beaLL /*  800 */,	0xb0b854a7fe42980fLL /*  801 */,
    0x7bd46a6a718d4b9fLL /*  802 */,	0xd10fa8cc22a5fd8cLL /*  803 */,
    0xd31484952be4bd31LL /*  804 */,	0xc7fa975fcb243847LL /*  805 */,
    0x4886ed1e5846c407LL /*  806 */,	0x28cddb791eb70b04LL /*  807 */,
    0xc2b00be2f573417fLL /*  808 */,	0x5c9590452180f877LL /*  809 */,
    0x7a6bddfff370eb00LL /*  810 */,	0xce509e38d6d9d6a4LL /*  811 */,
    0xebeb0f00647fa702LL /*  812 */,	0x1dcc06cf76606f06LL /*  813 */,
    0xe4d9f28ba286ff0aLL /*  814 */,	0xd85a305dc918c262LL /*  815 */,
    0x475b1d8732225f54LL /*  816 */,	0x2d4fb51668ccb5feLL /*  817 */,
    0xa679b9d9d72bba20LL /*  818 */,	0x53841c0d912d43a5LL /*  819 */,
    0x3b7eaa48bf12a4e8LL /*  820 */,	0x781e0e47f22f1ddfLL /*  821 */,
    0xeff20ce60ab50973LL /*  822 */,	0x20d261d19dffb742LL /*  823 */,
    0x16a12b03062a2e39LL /*  824 */,	0x1960eb2239650495LL /*  825 */,
    0x251c16fed50eb8b8LL /*  826 */,	0x9ac0c330f826016eLL /*  827 */,
    0xed152665953e7671LL /*  828 */,	0x02d63194a6369570LL /*  829 */,
    0x5074f08394b1c987LL /*  830 */,	0x70ba598c90b25ce1LL /*  831 */,
    0x794a15810b9742f6LL /*  832 */,	0x0d5925e9fcaf8c6cLL /*  833 */,
    0x3067716cd868744eLL /*  834 */,	0x910ab077e8d7731bLL /*  835 */,
    0x6a61bbdb5ac42f61LL /*  836 */,	0x93513efbf0851567LL /*  837 */,
    0xf494724b9e83e9d5LL /*  838 */,	0xe887e1985c09648dLL /*  839 */,
    0x34b1d3c675370cfdLL /*  840 */,	0xdc35e433bc0d255dLL /*  841 */,
    0xd0aab84234131be0LL /*  842 */,	0x08042a50b48b7eafLL /*  843 */,
    0x9997c4ee44a3ab35LL /*  844 */,	0x829a7b49201799d0LL /*  845 */,
    0x263b8307b7c54441LL /*  846 */,	0x752f95f4fd6a6ca6LL /*  847 */,
    0x927217402c08c6e5LL /*  848 */,	0x2a8ab754a795d9eeLL /*  849 */,
    0xa442f7552f72943dLL /*  850 */,	0x2c31334e19781208LL /*  851 */,
    0x4fa98d7ceaee6291LL /*  852 */,	0x55c3862f665db309LL /*  853 */,
    0xbd0610175d53b1f3LL /*  854 */,	0x46fe6cb840413f27LL /*  855 */,
    0x3fe03792df0cfa59LL /*  856 */,	0xcfe700372eb85e8fLL /*  857 */,
    0xa7be29e7adbce118LL /*  858 */,	0xe544ee5cde8431ddLL /*  859 */,
    0x8a781b1b41f1873eLL /*  860 */,	0xa5c94c78a0d2f0e7LL /*  861 */,
    0x39412e2877b60728LL /*  862 */,	0xa1265ef3afc9a62cLL /*  863 */,
    0xbcc2770c6a2506c5LL /*  864 */,	0x3ab66dd5dce1ce12LL /*  865 */,
    0xe65499d04a675b37LL /*  866 */,	0x7d8f523481bfd216LL /*  867 */,
    0x0f6f64fcec15f389LL /*  868 */,	0x74efbe618b5b13c8LL /*  869 */,
    0xacdc82b714273e1dLL /*  870 */,	0xdd40bfe003199d17LL /*  871 */,
    0x37e99257e7e061f8LL /*  872 */,	0xfa52626904775aaaLL /*  873 */,
    0x8bbbf63a463d56f9LL /*  874 */,	0xf0013f1543a26e64LL /*  875 */,
    0xa8307e9f879ec898LL /*  876 */,	0xcc4c27a4150177ccLL /*  877 */,
    0x1b432f2cca1d3348LL /*  878 */,	0xde1d1f8f9f6fa013LL /*  879 */,
    0x606602a047a7ddd6LL /*  880 */,	0xd237ab64cc1cb2c7LL /*  881 */,
    0x9b938e7225fcd1d3LL /*  882 */,	0xec4e03708e0ff476LL /*  883 */,
    0xfeb2fbda3d03c12dLL /*  884 */,	0xae0bced2ee43889aLL /*  885 */,
    0x22cb8923ebfb4f43LL /*  886 */,	0x69360d013cf7396dLL /*  887 */,
    0x855e3602d2d4e022LL /*  888 */,	0x073805bad01f784cLL /*  889 */,
    0x33e17a133852f546LL /*  890 */,	0xdf4874058ac7b638LL /*  891 */,
    0xba92b29c678aa14aLL /*  892 */,	0x0ce89fc76cfaadcdLL /*  893 */,
    0x5f9d4e0908339e34LL /*  894 */,	0xf1afe9291f5923b9LL /*  895 */,
    0x6e3480f60f4a265fLL /*  896 */,	0xeebf3a2ab29b841cLL /*  897 */,
    0xe21938a88f91b4adLL /*  898 */,	0x57dfeff845c6d3c3LL /*  899 */,
    0x2f006b0bf62caaf2LL /*  900 */,	0x62f479ef6f75ee78LL /*  901 */,
    0x11a55ad41c8916a9LL /*  902 */,	0xf229d29084fed453LL /*  903 */,
    0x42f1c27b16b000e6LL /*  904 */,	0x2b1f76749823c074LL /*  905 */,
    0x4b76eca3c2745360LL /*  906 */,	0x8c98f463b91691bdLL /*  907 */,
    0x14bcc93cf1ade66aLL /*  908 */,	0x8885213e6d458397LL /*  909 */,
    0x8e177df0274d4711LL /*  910 */,	0xb49b73b5503f2951LL /*  911 */,
    0x10168168c3f96b6bLL /*  912 */,	0x0e3d963b63cab0aeLL /*  913 */,
    0x8dfc4b5655a1db14LL /*  914 */,	0xf789f1356e14de5cLL /*  915 */,
    0x683e68af4e51dac1LL /*  916 */,	0xc9a84f9d8d4b0fd9LL /*  917 */,
    0x3691e03f52a0f9d1LL /*  918 */,	0x5ed86e46e1878e80LL /*  919 */,
    0x3c711a0e99d07150LL /*  920 */,	0x5a0865b20c4e9310LL /*  921 */,
    0x56fbfc1fe4f0682eLL /*  922 */,	0xea8d5de3105edf9bLL /*  923 */,
    0x71abfdb12379187aLL /*  924 */,	0x2eb99de1bee77b9cLL /*  925 */,
    0x21ecc0ea33cf4523LL /*  926 */,	0x59a4d7521805c7a1LL /*  927 */,
    0x3896f5eb56ae7c72LL /*  928 */,	0xaa638f3db18f75dcLL /*  929 */,
    0x9f39358dabe9808eLL /*  930 */,	0xb7defa91c00b72acLL /*  931 */,
    0x6b5541fd62492d92LL /*  932 */,	0x6dc6dee8f92e4d5bLL /*  933 */,
    0x353f57abc4beea7eLL /*  934 */,	0x735769d6da5690ceLL /*  935 */,
    0x0a234aa642391484LL /*  936 */,	0xf6f9508028f80d9dLL /*  937 */,
    0xb8e319a27ab3f215LL /*  938 */,	0x31ad9c1151341a4dLL /*  939 */,
    0x773c22a57bef5805LL /*  940 */,	0x45c7561a07968633LL /*  941 */,
    0xf913da9e249dbe36LL /*  942 */,	0xda652d9b78a64c68LL /*  943 */,
    0x4c27a97f3bc334efLL /*  944 */,	0x76621220e66b17f4LL /*  945 */,
    0x967743899acd7d0bLL /*  946 */,	0xf3ee5bcae0ed6782LL /*  947 */,
    0x409f753600c879fcLL /*  948 */,	0x06d09a39b5926db6LL /*  949 */,
    0x6f83aeb0317ac588LL /*  950 */,	0x01e6ca4a86381f21LL /*  951 */,
    0x66ff3462d19f3025LL /*  952 */,	0x72207c24ddfd3bfbLL /*  953 */,
    0x4af6b6d3e2ece2ebLL /*  954 */,	0x9c994dbec7ea08deLL /*  955 */,
    0x49ace597b09a8bc4LL /*  956 */,	0xb38c4766cf0797baLL /*  957 */,
    0x131b9373c57c2a75LL /*  958 */,	0xb1822cce61931e58LL /*  959 */,
    0x9d7555b909ba1c0cLL /*  960 */,	0x127fafdd937d11d2LL /*  961 */,
    0x29da3badc66d92e4LL /*  962 */,	0xa2c1d57154c2ecbcLL /*  963 */,
    0x58c5134d82f6fe24LL /*  964 */,	0x1c3ae3515b62274fLL /*  965 */,
    0xe907c82e01cb8126LL /*  966 */,	0xf8ed091913e37fcbLL /*  967 */,
    0x3249d8f9c80046c9LL /*  968 */,	0x80cf9bede388fb63LL /*  969 */,
    0x1881539a116cf19eLL /*  970 */,	0x5103f3f76bd52457LL /*  971 */,
    0x15b7e6f5ae47f7a8LL /*  972 */,	0xdbd7c6ded47e9ccfLL /*  973 */,
    0x44e55c410228bb1aLL /*  974 */,	0xb647d4255edb4e99LL /*  975 */,
    0x5d11882bb8aafc30LL /*  976 */,	0xf5098bbb29d3212aLL /*  977 */,
    0x8fb5ea14e90296b3LL /*  978 */,	0x677b942157dd025aLL /*  979 */,
    0xfb58e7c0a390acb5LL /*  980 */,	0x89d3674c83bd4a01LL /*  981 */,
    0x9e2da4df4bf3b93bLL /*  982 */,	0xfcc41e328cab4829LL /*  983 */,
    0x03f38c96ba582c52LL /*  984 */,	0xcad1bdbd7fd85db2LL /*  985 */,
    0xbbb442c16082ae83LL /*  986 */,	0xb95fe86ba5da9ab0LL /*  987 */,
    0xb22e04673771a93fLL /*  988 */,	0x845358c9493152d8LL /*  989 */,
    0xbe2a488697b4541eLL /*  990 */,	0x95a2dc2dd38e6966LL /*  991 */,
    0xc02c11ac923c852bLL /*  992 */,	0x2388b1990df2a87bLL /*  993 */,
    0x7c8008fa1b4f37beLL /*  994 */,	0x1f70d0c84d54e503LL /*  995 */,
    0x5490adec7ece57d4LL /*  996 */,	0x002b3c27d9063a3aLL /*  997 */,
    0x7eaea3848030a2bfLL /*  998 */,	0xc602326ded2003c0LL /*  999 */,
    0x83a7287d69a94086LL /* 1000 */,	0xc57a5fcb30f57a8aLL /* 1001 */,
    0xb56844e479ebe779LL /* 1002 */,	0xa373b40f05dcbce9LL /* 1003 */,
    0xd71a786e88570ee2LL /* 1004 */,	0x879cbacdbde8f6a0LL /* 1005 */,
    0x976ad1bcc164a32fLL /* 1006 */,	0xab21e25e9666d78bLL /* 1007 */,
    0x901063aae5e5c33cLL /* 1008 */,	0x9818b34448698d90LL /* 1009 */,
    0xe36487ae3e1e8abbLL /* 1010 */,	0xafbdf931893bdcb4LL /* 1011 */,
    0x6345a0dc5fbbd519LL /* 1012 */,	0x8628fe269b9465caLL /* 1013 */,
    0x1e5d01603f9c51ecLL /* 1014 */,	0x4de44006a15049b7LL /* 1015 */,
    0xbf6c70e5f776cbb1LL /* 1016 */,	0x411218f2ef552bedLL /* 1017 */,
    0xcb0c0708705a36a3LL /* 1018 */,	0xe74d14754f986044LL /* 1019 */,
    0xcd56d9430ea8280eLL /* 1020 */,	0xc12591d7535f5065LL /* 1021 */,
    0xc83223f1720aef96LL /* 1022 */,	0xc3a0396f7363a51fLL /* 1023 */
};


static void
print_abc( const char *text, u64 a, u64 b, u64 c )
{
/*printf("%s: %08X%08X %08X%08X %08X%08X\n",
	 text,
	 (u32)(a>>32),
	 (u32)(a),
	 (u32)(b>>32),
	 (u32)(b),
	 (u32)(c>>32),
	 (u32)(c) );*/
}

static void
print_data( const char *text, u64 a, u64 b, u64 c,
			      u64 d, u64 e, u64 f,
			      u64 g, u64 h )
{
/*printf("%s: %08X%08X %08X%08X %08X%08X %08X%08X\n"
	 "%s  %08X%08X %08X%08X %08X%08X %08X%08X\n",
	 text,
	 (u32)(a>>32),
	 (u32)(a),
	 (u32)(b>>32),
	 (u32)(b),
	 (u32)(c>>32),
	 (u32)(c),
	 (u32)(d>>32),
	 (u32)(d),
	 text,
	 (u32)(e>>32),
	 (u32)(e),
	 (u32)(f>>32),
	 (u32)(f),
	 (u32)(g>>32),
	 (u32)(g),
	 (u32)(h>>32),
	 (u32)(h) );*/
}


static void
burn_stack (int bytes)
{
    char buf[256];
    
    memset (buf, 0, sizeof buf);
    bytes -= sizeof buf;
    if (bytes > 0)
        burn_stack (bytes);
}



static void
tiger_init( TIGER_CONTEXT *hd )
{
    hd->a = 0x0123456789abcdefLL;
    hd->b = 0xfedcba9876543210LL;
    hd->c = 0xf096a5b4c3b2e187LL;
    hd->nblocks = 0;
    hd->count = 0;
}

static void
round( u64 *ra, u64 *rb, u64 *rc, u64 x, int mul )
{
    u64 a = *ra;
    u64 b = *rb;
    u64 c = *rc;

    c ^= x;
    a -=   sbox1[  c	    & 0xff ] ^ sbox2[ (c >> 16) & 0xff ]
	 ^ sbox3[ (c >> 32) & 0xff ] ^ sbox4[ (c >> 48) & 0xff ];
    b +=   sbox4[ (c >>  8) & 0xff ] ^ sbox3[ (c >> 24) & 0xff ]
	 ^ sbox2[ (c >> 40) & 0xff ] ^ sbox1[ (c >> 56) & 0xff ];
    b *= mul;

    *ra = a;
    *rb = b;
    *rc = c;
}


static void
pass( u64 *ra, u64 *rb, u64 *rc, u64 *x, int mul )
{
    u64 a = *ra;
    u64 b = *rb;
    u64 c = *rc;

    round( &a, &b, &c, x[0], mul );
    round( &b, &c, &a, x[1], mul );
    round( &c, &a, &b, x[2], mul );
    round( &a, &b, &c, x[3], mul );
    round( &b, &c, &a, x[4], mul );
    round( &c, &a, &b, x[5], mul );
    round( &a, &b, &c, x[6], mul );
    round( &b, &c, &a, x[7], mul );

    *ra = a;
    *rb = b;
    *rc = c;
}


static void
key_schedule( u64 *x )
{
    x[0] -= x[7] ^ 0xa5a5a5a5a5a5a5a5LL;
    x[1] ^= x[0];
    x[2] += x[1];
    x[3] -= x[2] ^ ((~x[1]) << 19 );
    x[4] ^= x[3];
    x[5] += x[4];
    x[6] -= x[5] ^ ((~x[4]) >> 23 );
    x[7] ^= x[6];
    x[0] += x[7];
    x[1] -= x[0] ^ ((~x[7]) << 19 );
    x[2] ^= x[1];
    x[3] += x[2];
    x[4] -= x[3] ^ ((~x[2]) >> 23 );
    x[5] ^= x[4];
    x[6] += x[5];
    x[7] -= x[6] ^ 0x0123456789abcdefLL;
}


/****************
 * Transform the message DATA which consists of 512 bytes (8 words)
 */
static void
transform( TIGER_CONTEXT *hd, byte *data )
{
    u64 a,b,c,aa,bb,cc;
    u64 x[8];
  #ifdef BIG_ENDIAN_HOST
    #define MKWORD(d,n) \
		(  ((u64)(d)[8*(n)+7]) << 56 | ((u64)(d)[8*(n)+6]) << 48  \
		 | ((u64)(d)[8*(n)+5]) << 40 | ((u64)(d)[8*(n)+4]) << 32  \
		 | ((u64)(d)[8*(n)+3]) << 24 | ((u64)(d)[8*(n)+2]) << 16  \
		 | ((u64)(d)[8*(n)+1]) << 8  | ((u64)(d)[8*(n)	])	 )
    x[0] = MKWORD(data, 0);
    x[1] = MKWORD(data, 1);
    x[2] = MKWORD(data, 2);
    x[3] = MKWORD(data, 3);
    x[4] = MKWORD(data, 4);
    x[5] = MKWORD(data, 5);
    x[6] = MKWORD(data, 6);
    x[7] = MKWORD(data, 7);
    #undef MKWORD
  #else
    memcpy( &x[0], data, 64 );
  #endif

    /* save */
    a = aa = hd->a;
    b = bb = hd->b;
    c = cc = hd->c;

    print_data(" key0", x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7] );
    print_abc(" init", a, b, c );
    pass( &a, &b, &c, x, 5);
    print_abc("pass1", a, b, c );
    key_schedule( x );
    pass( &c, &a, &b, x, 7);
    print_abc("pass2", a, b, c );
    key_schedule( x );
    pass( &b, &c, &a, x, 9);
    print_abc("pass3", a, b, c );


    /* feedforward */
    a ^= aa;
    b -= bb;
    c += cc;
    /* store */
    hd->a = a;
    hd->b = b;
    hd->c = c;
}



/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
static void
tiger_write( TIGER_CONTEXT *hd, byte *inbuf, size_t inlen)
{
    if( hd->count == 64 ) { /* flush the buffer */
	transform( hd, hd->buf );
        burn_stack (21*8+11*sizeof(void*));
	hd->count = 0;
	hd->nblocks++;
    }
    if( !inbuf )
	return;
    if( hd->count ) {
	for( ; inlen && hd->count < 64; inlen-- )
	    hd->buf[hd->count++] = *inbuf++;
	tiger_write( hd, NULL, 0 );
	if( !inlen )
	    return;
    }

    while( inlen >= 64 ) {
	transform( hd, inbuf );
	hd->count = 0;
	hd->nblocks++;
	inlen -= 64;
	inbuf += 64;
    }
    burn_stack (21*8+11*sizeof(void*));
    for( ; inlen && hd->count < 64; inlen-- )
	hd->buf[hd->count++] = *inbuf++;
}



/* The routine terminates the computation
 */

static void
tiger_final( TIGER_CONTEXT *hd )
{
    u32 t, msb, lsb;
    byte *p;

    tiger_write(hd, NULL, 0); /* flush */;

    t = hd->nblocks;
    /* multiply by 64 to make a byte count */
    lsb = t << 6;
    msb = t >> 26;
    /* add the count */
    t = lsb;
    if( (lsb += hd->count) < t )
	msb++;
    /* multiply by 8 to make a bit count */
    t = lsb;
    lsb <<= 3;
    msb <<= 3;
    msb |= t >> 29;

    if( hd->count < 56 ) { /* enough room */
	hd->buf[hd->count++] = 0x01; /* pad */
	while( hd->count < 56 )
	    hd->buf[hd->count++] = 0;  /* pad */
    }
    else { /* need one extra block */
	hd->buf[hd->count++] = 0x01; /* pad character */
	while( hd->count < 64 )
	    hd->buf[hd->count++] = 0;
	tiger_write(hd, NULL, 0);  /* flush */;
	memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
    }
    /* append the 64 bit count */
    hd->buf[56] = lsb	   ;
    hd->buf[57] = lsb >>  8;
    hd->buf[58] = lsb >> 16;
    hd->buf[59] = lsb >> 24;
    hd->buf[60] = msb	   ;
    hd->buf[61] = msb >>  8;
    hd->buf[62] = msb >> 16;
    hd->buf[63] = msb >> 24;
    transform( hd, hd->buf );
    burn_stack (21*8+11*sizeof(void*));

    p = hd->buf;
  #ifdef BIG_ENDIAN_HOST
    #define X(a) do { *(u64*)p = hd-> a ; p += 8; } while(0)
  #else /* little endian */
    #define X(a) do { *p++ = hd-> a >> 56; *p++ = hd-> a >> 48; \
		      *p++ = hd-> a >> 40; *p++ = hd-> a >> 32; \
		      *p++ = hd-> a >> 24; *p++ = hd-> a >> 16; \
		      *p++ = hd-> a >>  8; *p++ = hd-> a; } while(0)
  #endif
    X(a);
    X(b);
    X(c);
  #undef X
}

static byte *
tiger_read( TIGER_CONTEXT *hd )
{
    return hd->buf;
}

#endif /*HAVE_U64_TYPEDEF*/

/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 */
const char *
tiger_get_info( int algo, size_t *contextsize,
	       byte **r_asnoid, int *r_asnlen, int *r_mdlen,
	       void (**r_init)( void *c ),
	       void (**r_write)( void *c, byte *buf, size_t nbytes ),
	       void (**r_final)( void *c ),
	       byte *(**r_read)( void *c )
	     )
{
#ifdef HAVE_U64_TYPEDEF

#ifdef USE_OLD_TIGER
    /* This is the old fake OID */
    static byte asn[18] =
      { 0x30, 0x28, 0x30, 0x0c, 0x04, 0x08, 0x54, 0x49, 0x47,
	0x45, 0x52, 0x31, 0x39, 0x32, 0x05, 0x00, 0x04, 0x18 };
#else /* !USE_OLD_TIGER */
    /* This is the new correct OID */
    static byte asn[19] = /* Object ID is 1.3.6.1.4.1.11591.12.2 */
                         { 0x30, 0x29, 0x30, 0x0d, 0x06, 0x09, 0x2b, 0x06,
                           0x01, 0x04, 0x01, 0xda, 0x47, 0x0c, 0x02,
                           0x05, 0x00, 0x04, 0x18 };
#endif

    if( algo != 6 )
	return NULL;

    *contextsize = sizeof(TIGER_CONTEXT);
    *r_asnoid = asn;
    *r_asnlen = DIM(asn);
    *r_mdlen = 24;
    *(void  (**)(TIGER_CONTEXT *))r_init		 = tiger_init;
    *(void  (**)(TIGER_CONTEXT *, byte*, size_t))r_write = tiger_write;
    *(void  (**)(TIGER_CONTEXT *))r_final		 = tiger_final;
    *(byte *(**)(TIGER_CONTEXT *))r_read		 = tiger_read;

    return "TIGER192";
#else /*!HAVE_U64_TYPEDEF*/
    return NULL; /* Alorithm not available. */
#endif
}
