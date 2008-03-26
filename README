
		    GnuPG - The GNU Privacy Guard
		   -------------------------------
			    Version 1.4.9

	 Copyright 1998, 1999, 2000, 2001, 2002, 2003, 2004,
	   2005, 2006, 2007, 2008 Free Software Foundation, Inc.

    This file is free software; as a special exception the author
    gives unlimited permission to copy and/or distribute it, with or
    without modifications, as long as this notice is preserved.

    This file is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY, to the extent permitted by law; without even
    the implied warranty of MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.


    Intro
    -----

    GnuPG is GNU's tool for secure communication and data storage.
    It can be used to encrypt data and to create digital signatures.
    It includes an advanced key management facility and is compliant
    with the proposed OpenPGP Internet standard as described in RFC2440.

    GnuPG works best on GNU/Linux or *BSD systems.  Most other Unices
    are also supported but are not as well tested as the Free Unices.
    See http://www.gnupg.org/download/supported_systems.html for a
    list of systems which are known to work.

    See the file COPYING for copyright and warranty information.

    Because GnuPG does not use use any patented algorithms it is not
    by default fully compatible with PGP 2.x, which uses the patented
    IDEA algorithm.  See http://www.gnupg.org/why-not-idea.html for
    more information on this subject, including what to do if you are
    legally entitled to use IDEA.

    The default public key algorithms are DSA and Elgamal, but RSA is
    also supported.  Symmetric algorithms available are AES (with 128,
    192, and 256 bit keys), 3DES, Blowfish, CAST5 and Twofish.  Digest
    algorithms available are MD5, RIPEMD/160, SHA-1, SHA-256, SHA-384,
    and SHA-512.  Compression algorithms available are ZIP, ZLIB, and
    BZIP2 (with libbz2 installed).


    Installation
    ------------

    Please read the file INSTALL and the sections in this file
    related to the installation.  Here is a quick summary:

    1) Check that you have unmodified sources.  See below on how to do
       this.  Don't skip it - this is an important step!

    2) Unpack the tarball.  With GNU tar you can do it this way:
       "tar xzvf gnupg-x.y.z.tar.gz".  If got a bzip2 compressed
       tarball you need to use: "tar xjvf gnupg-x.y.z.tar.bz2".

    3) "cd gnupg-x.y.z"

    4) "./configure"

    5) "make"

    6) "make install"

    7) You end up with a "gpg" binary in /usr/local/bin.

    8) To avoid swapping out of sensitive data, you can install "gpg"
       setuid root.  If you don't do so, you may want to add the
       option "no-secmem-warning" to ~/.gnupg/gpg.conf


    How to Verify the Source
    ------------------------

    In order to check that the version of GnuPG which you are going to
    install is an original and unmodified one, you can do it in one of
    the following ways:

    a) If you already have a trusted Version of GnuPG installed, you
       can simply check the supplied signature:

	$ gpg --verify gnupg-x.y.z.tar.gz.sig

       This checks that the detached signature gnupg-x.y.z.tar.gz.sig
       is indeed a signature of gnupg-x.y.z.tar.gz.  The key currently
       used to create this signature is:

       "pub  1024R/1CE0C630 2006-01-01 Werner Koch (dist sig) <dd9jn@gnu.org>"

       If you do not have this key, you can get it from the source in
       the file doc/samplekeys.asc (use "gpg --import  doc/samplekeys.asc"
       to add it to the keyring) or from any keyserver.  You have to
       make sure that this is really the key and not a faked one. You
       can do this by comparing the output of:

        $ gpg --fingerprint 0x1CE0C630

       with the fingerprint published elsewhere.

       Please note, that you have to use an old version of GnuPG to
       do all this stuff.  *Never* use the version which you are going
       to check!


    b) If you don't have any of the above programs, you have to verify
       the SHA1 checksum:

	$ sha1sum gnupg-x.y.z.tar.gz

       This should yield an output _similar_ to this:

	fd9351b26b3189c1d577f0970f9dcadc1234abcd  gnupg-x.y.z.tar.gz

       Now check that this checksum is _exactly_ the same as the one
       published via the announcement list and probably via Usenet.


    Documentation
    -------------

    The manual will be distributed separately under the name "gph".
    An online version of the latest manual draft is available at the
    GnuPG web pages:

	http://www.gnupg.org/documentation/

    A list of frequently asked questions is available in the GnuPG
    distribution in the file doc/FAQ and online as:

	http://www.gnupg.org/documentation/faqs.html

    A couple of HOWTO documents are available online; for a listing see:

	http://www.gnupg.org/documentation/howtos.html

    A man page with a description of all commands and options gets installed
    along with the program. 


    Introduction
    ------------

    Here is a brief overview on how to use GnuPG - it is strongly suggested
    that you read the manual and other information about the use of
    cryptography.  GnuPG is only a tool, secure usage requires that
    YOU KNOW WHAT YOU ARE DOING.

    The first time you run gpg, it will create a .gnupg directory in
    your home directory and populate it with a default configuration
    file.  Once this is done, you may create a new key, or if you
    already have keyrings from PGP, you can import them into GnuPG
    with:

        gpg --import path/to/pgp/keyring/pubring.pkr
    and
        gpg --import path/to/pgp/keyring/secring.skr

    The normal way to create a key is

	gpg --gen-key

    This asks some questions and then starts key generation. To create
    good random numbers for the key parameters, GnuPG needs to gather
    enough noise (entropy) from your system.  If you see no progress
    during key generation you should start some other activities such
    as moving the mouse or hitting the CTRL and SHIFT keys.

    Generate a key ONLY on a machine where you have direct physical
    access - don't do it over the network or on a machine also used
    by others, especially if you have no access to the root account.

    When you are asked for a passphrase use a good one which you can
    easily remember.  Don't make the passphrase too long because you
    have to type it for every decryption or signing; but, - AND THIS
    IS VERY IMPORTANT - use a good one that is not easily to guess
    because the security of the whole system relies on your secret key
    and the passphrase that protects it when someone gains access to
    your secret keyring.  One good way to select a passphrase is to
    figure out a short nonsense sentence which makes some sense for
    you and modify it by inserting extra spaces, non-letters and
    changing the case of some characters - this is really easy to
    remember especially if you associate some pictures with it.

    Next, you should create a revocation certificate in case someone
    gets knowledge of your secret key or you forgot your passphrase

	gpg --gen-revoke your_user_id

    Run this command and store the revocation certificate away.  The output
    is always ASCII armored, so that you can print it and (hopefully
    never) re-create it if your electronic media fails.

    Now you can use your key to create digital signatures

	gpg -s file

    This creates a file "file.gpg" which is compressed and has a
    signature attached.

	gpg -sa file

    Same as above, but creates a file "file.asc" which is ASCII armored
    and and ready for sending by mail.	It is better to use your
    mailers features to create signatures (The mailer uses GnuPG to do
    this) because the mailer has the ability to MIME encode such
    signatures - but this is not a security issue.

	gpg -s -o out file

    Creates a signature of "file", but writes the output to the file
    "out".

    Everyone who knows your public key (you can and should publish
    your key by putting it on a key server, a web page or in your .plan
    file) is now able to check whether you really signed this text

	gpg --verify file

    GnuPG now checks whether the signature is valid and prints an
    appropriate message.  If the signature is good, you know at least
    that the person (or machine) has access to the secret key which
    corresponds to the published public key.

    If you run gpg without an option it will verify the signature and
    create a new file that is identical to the original.  gpg can also
    run as a filter, so that you can pipe data to verify trough it

	cat signed-file | gpg | wc -l

    which will check the signature of signed-file and then display the
    number of lines in the original file.

    To send a message encrypted to someone you can use

	gpg -e -r heine file

    This encrypts "file" with the public key of the user "heine" and
    writes it to "file.gpg"

	echo "hello" | gpg -ea -r heine | mail heine

    Ditto, but encrypts "hello\n" and mails it as ASCII armored message
    to the user with the mail address heine.

	gpg -se -r heine file

    This encrypts "file" with the public key of "heine" and writes it
    to "file.gpg" after signing it with your user id.

	gpg -se -r heine -u Suttner file

    Ditto, but sign the file with your alternative user id "Suttner"


    GnuPG has some options to help you publish public keys.  This is
    called "exporting" a key, thus

	gpg --export >all-my-keys

    exports all the keys in the keyring and writes them (in a binary
    format) to "all-my-keys".  You may then mail "all-my-keys" as an
    MIME attachment to someone else or put it on an FTP server. To
    export only some user IDs, you give them as arguments on the command
    line.

    To mail a public key or put it on a web page you have to create
    the key in ASCII armored format

	gpg --export --armor | mail panther@tiger.int

    This will send all your public keys to your friend panther.

    If you have received a key from someone else you can put it
    into your public keyring.  This is called "importing"

	gpg --import [filenames]

    New keys are appended to your keyring and already existing
    keys are updated. Note that GnuPG does not import keys that
    are not self-signed.

    Because anyone can claim that a public key belongs to her
    we must have some way to check that a public key really belongs
    to the owner.  This can be achieved by comparing the key during
    a phone call.  Sure, it is not very easy to compare a binary file
    by reading the complete hex dump of the file - GnuPG (and nearly
    every other program used for management of cryptographic keys)
    provides other solutions.

	gpg --fingerprint <username>

    prints the so called "fingerprint" of the given username which
    is a sequence of hex bytes (which you may have noticed in mail
    sigs or on business cards) that uniquely identifies the public
    key - different keys will always have different fingerprints.
    It is easy to compare fingerprints by phone and I suggest
    that you print your fingerprint on the back of your business
    card.  To see the fingerprints of the secondary keys, you can
    give the command twice; but this is normally not needed.

    If you don't know the owner of the public key you are in trouble.
    Suppose however that friend of yours knows someone who knows someone
    who has met the owner of the public key at some computer conference.
    Suppose that all the people between you and the public key holder
    may now act as introducers to you.	Introducers signing keys thereby
    certify that they know the owner of the keys they sign.  If you then
    trust all the introducers to have correctly signed other keys, you
    can be be sure that the other key really belongs to the one who
    claims to own it.

    There are 2 steps to validate a key:
	1. First check that there is a complete chain
	   of signed keys from the public key you want to use
	   and your key and verify each signature.
	2. Make sure that you have full trust in the certificates
	   of all the introduces between the public key holder and
	   you.
    Step 2 is the more complicated part because there is no easy way
    for a computer to decide who is trustworthy and who is not.  GnuPG
    leaves this decision to you and will ask you for a trust value
    (here also referenced as the owner-trust of a key) for every key
    needed to check the chain of certificates.	You may choose from:
      a) "I don't know" - then it is not possible to use any
	 of the chains of certificates, in which this key is used
	 as an introducer, to validate the target key.	Use this if
	 you don't know the introducer.
      b) "I do not trust" - Use this if you know that the introducer
	 does not do a good job in certifying other keys.  The effect
	 is the same as with a) but for a) you may later want to
	 change the value because you got new information about this
	 introducer.
      c) "I trust marginally" - Use this if you assume that the
	 introducer knows what he is doing.  Together with some
	 other marginally trusted keys, GnuPG validates the target
	 key then as good.
      d) "I fully trust" - Use this if you really know that this
	 introducer does a good job when certifying other keys.
	 If all the introducer are of this trust value, GnuPG
	 normally needs only one chain of signatures to validate
	 a target key okay. (But this may be adjusted with the help
	 of some options).
    This information is confidential because it gives your personal
    opinion on the trustworthiness of someone else.  Therefore this data
    is not stored in the keyring but in the "trustdb"
    (~/.gnupg/trustdb.gpg).  Do not assign a high trust value just
    because the introducer is a friend of yours - decide how well she
    understands the implications of key signatures and you may want to
    tell her more about public key cryptography so you can later change
    the trust value you assigned.

    Okay, here is how GnuPG helps you with key management.  Most stuff
    is done with the --edit-key command

	gpg --edit-key <keyid or username>

    GnuPG displays some information about the key and then prompts
    for a command (enter "help" to see a list of commands and see
    the man page for a more detailed explanation).  To sign a key
    you select the user ID you want to sign by entering the number
    that is displayed in the leftmost column (or do nothing if the
    key has only one user ID) and then enter the command "sign" and
    follow all the prompts.  When you are ready, give the command
    "save" (or use "quit" to cancel your actions).

    If you want to sign the key with another of your user IDs, you
    must give an "-u" option on the command line together with the
    "--edit-key".

    Normally you want to sign only one user ID because GnuPG
    uses only one and this keeps the public key certificate
    small.  Because such key signatures are very important you
    should make sure that the signatories of your key sign a user ID
    which is very likely to stay for a long time - choose one with an
    email address you have full control of or do not enter an email
    address at all.  In future GnuPG will have a way to tell which
    user ID is the one with an email address you prefer - because
    you have no signatures on this email address it is easy to change
    this address.  Remember, your signatories sign your public key (the
    primary one) together with one of your user IDs - so it is not possible
    to change the user ID later without voiding all the signatures.

    Tip: If you hear about a key signing party on a computer conference
    join it because this is a very convenient way to get your key
    certified (But remember that signatures have nothing to to with the
    trust you assign to a key).


    8 Ways to Specify a User ID
    ---------=-----------------

    There are several ways to specify a user ID, here are some examples.

    * Only by the short keyid (prepend a zero if it begins with A..F):

	"234567C4"
	"0F34E556E"
	"01347A56A"
	"0xAB123456

    * By a complete keyid:

	"234AABBCC34567C4"
	"0F323456784E56EAB"
	"01AB3FED1347A5612"
	"0x234AABBCC34567C4"

    * By a fingerprint:

	"1234343434343434C434343434343434"
	"123434343434343C3434343434343734349A3434"
	"0E12343434343434343434EAB3484343434343434"

      The first one is a short fingerprint for PGP 2.x style keys.
      The others are long fingerprints for OpenPGP keys.

    * By an exact string:

	"=Heinrich Heine <heinrichh@uni-duesseldorf.de>"

    * By an email address:

	"<heinrichh@uni-duesseldorf.de>"

    * By word match

	"+Heinrich Heine duesseldorf"

      All words must match exactly (not case sensitive) and appear in
      any order in the user ID.  Words are any sequences of letters,
      digits, the underscore and characters with bit 7 set.

    * Or by the usual substring:

	"Heine"
	"*Heine"

      The '*' indicates substring search explicitly.


    Batch mode
    ----------

    If you use the option "--batch", GnuPG runs in non-interactive mode and
    never prompts for input data.  This does not even allow entering the
    passphrase.  Until we have a better solution (something like ssh-agent),
    you can use the option "--passphrase-fd n", which works like PGP's
    PGPPASSFD.

    Batch mode also causes GnuPG to terminate as soon as a BAD signature is
    detected.


    Exit status
    -----------

    GnuPG returns with an exit status of 1 if in batch mode and a bad signature
    has been detected or 2 or higher for all other errors.  You should parse
    stderr or, better, the output of the fd specified with --status-fd to get
    detailed information about the errors.


    Configure options 
    -----------------

    Here is a list of configure options which are sometime useful 
    for installation.

    --enable-static-rnd=<name> 
                     Force the use of the random byte gathering
		     module <name>.  Default is either to use /dev/random
		     or the auto mode.  Value for name:
		       egd - Use the module which accesses the
			     Entropy Gathering Daemon. See the webpages
			     for more information about it.
		      unix - Use the standard Unix module which does not
			     have a very good performance.
		     linux - Use the module which accesses /dev/random.
			     This is the first choice and the default one
			     for GNU/Linux or *BSD.
                      auto - Compile linux, egd and unix in and 
                             automagically select at runtime.
  
     --with-egd-socket=<name>
                     This is only used when EGD is used as random
                     gatherer. GnuPG uses by default "~/.gnupg/entropy"
                     as the socket to connect EGD.  Using this option the
                     socket name can be changed.  You may use any filename
                     here with 2 exceptions:  a filename starting with
                     "~/" uses the socket in the home directory of the user
                     and one starting with a "=" uses a socket in the
                     GnuPG home directory which is "~/.gnupg" by default.
 
     --without-readline
                     Do not include support for the readline library
                     even if it is available.  The default is to check
                     whether the readline library is a available and
                     use it to allow fancy command line editing.
  
     --with-included-zlib
                     Forces usage of the local zlib sources. Default is
		     to use the (shared) library of the system.

     --with-zlib=<DIR>
		     Look for the system zlib in DIR.

     --with-bzip2=<DIR>
		     Look for the system libbz2 in DIR.

     --without-bzip2
		     Disable the BZIP2 compression algorithm.

     --with-included-gettext
                     Forces usage of the local gettext sources instead of
		     the one provided by your system.

     --disable-nls
                     Disable NLS support (See the file ABOUT-NLS)

     --enable-m-guard
                     Enable the integrated malloc checking code. Please
                     note that this feature does not work on all CPUs
                     (e.g. SunOS 5.7 on UltraSparc-2) and might give
                     you a bus error.

     --disable-dynload 
                    If you have problems with dynamic loading, this
                    option disables all dynamic loading stuff.  Note
                    that the use of dynamic linking is very limited.

     --disable-asm
                    Do not use assembler modules.  It is not possible 
                    to use this on some CPU types.
                    
     --disable-exec
                    Disable all remote program execution.  This
		    disables photo ID viewing as well as all keyserver
		    access.

     --disable-photo-viewers
                    Disable only photo ID viewing.

     --disable-keyserver-helpers
                    Disable only keyserver helpers.

     --disable-keyserver-path
                    Disables the user's ability to use the exec-path
		    feature to add additional search directories when
		    executing a keyserver helper.

     --with-photo-viewer=FIXED_VIEWER
                    Force the photo viewer to be FIXED_VIEWER and
		    disable any ability for the user to change it in
		    their options file.

     --disable-rsa
		    Removes support for the RSA public key algorithm.
                    This can give a smaller gpg binary for places
                    where space is tight.

     --disable-idea
     --disable-cast5
     --disable-blowfish
     --disable-aes
     --disable-twofish
     --disable-sha256
     --disable-sha512
		    Removes support for the selected symmetric or hash
		    algorithm.  This can give a smaller gpg binary for
		    places where space is tight.

		    **** Note that if there are existing keys that
		    have one of these algorithms as a preference,
		    messages may be received that use one of these
		    algorithms and you will not be able to decrypt the
		    message! ****

		    The public key preference list can be updated to
		    match the list of available algorithms by using
		    "gpg --edit-key (thekey)", and running the
		    "setpref" command.

     --enable-minimal
		    Build the smallest gpg binary possible (disables
		    all optional algorithms, disables keyserver
		    access, and disables photo IDs).  Specifically,
		    this means --disable-rsa --disable-idea,
		    --disable-cast5, --disable-blowfish,
		    --disable-aes, --disable-twofish,
		    --disable-sha256, --disable-sha512,
		    --without-bzip2, --disable-exec, 
                    --disable-card-support and
		    --disable-agent-support.
                    Configure command lines are read from left to
		    right, so if you want to have an "almost minimal"
		    configuration, you can do (for example)
		    "--enable-minimal --enable-rsa" to have RSA added
		    to the minimal build.

     --enable-key-cache=SIZE
                    Set the internal key and UID cache size.  This has
                    a significant impact on performance with large
                    keyrings.  The default is 4096, but for use on
                    platforms where memory is an issue, it can be set
                    as low as 5.

     --disable-card-support
                    Do not include smartcard support.  The default is
                    to include support if all required libraries are
                    available.

     --disable-agent-support
                    Do not include support for the gpg-agent.  The
                    default is to include support.

     --enable-selinux-support
                    This prevents access to certain files and won't
                    allow import or export of secret keys. 

     --enable-noexecstack
                    Pass option --noexecstack to as.  Autdetect wether
                    the tool chain actually support this.

     --disable-gnupg-iconv
                    If iconv is available it is used to convert
                    between utf-8 and the system character set.  This
                    is in general the preferable solution.  However
                    the code is new and under some cirumstances it may
                    give different output than with the limited old
                    support.  This option allows to explicity disable
                    the use of iconv.  Note, that iconv is also
                    disabled if gettext has been disabled.


    Installation Problems
    ---------------------

    If you get unresolved externals "gettext" you should run configure
    again with the option "--with-included-gettext"; this is version
    0.12.1 which is available at ftp.gnu.org.

    If you have other compile problems, try the configure options
    "--with-included-zlib" or "--disable-nls" (See ABOUT-NLS) or
    --disable-dynload.

    We can't check all assembler files, so if you have problems
    assembling them (or the program crashes) use --disable-asm with
    ./configure.  If you opt to delete individual replacement files in
    hopes of using the remaining ones, be aware that the configure
    scripts may consider several subdirectories to get all available
    assembler files; be sure to delete the correct ones. The assembler
    replacements are in C and in mpi/generic; never delete
    udiv-qrnnd.S in any CPU directory, because there may be no C
    substitute.  Don't forget to delete "config.cache" and run
    "./config.status --recheck".  We have also heard reports of
    problems when using versions of gcc earlier than 2.96 along with a
    non-GNU assembler (as).  If this applies to your platform, you can
    either upgrade gcc to a more recent version, or use the GNU
    assembler.

    Some make tools are broken - the best solution is to use GNU's
    make.  Try gmake or grab the sources from a GNU archive and
    install them.

    On some OSF systems you may get unresolved externals.  This is a
    libtool problem and the workaround is to manually remove all the
    "-lc -lz" but the last one from the linker line and execute them
    manually.

    On some architectures you see warnings like:
      longlong.h:175: warning: function declaration isn't a prototype
    or
      http.c:647: warning: cast increases required alignment of target type
    This doesn't matter and we know about it (actually it is due to
    some warning options which we have enabled for gcc)

    If you are cross-compiling and you get an error either building a
    tool called "yat2m" or running that tool, the problem is most
    likely a bad or missing native compiler.  We require a standard
    C-89 compiler to produce an executable to be run on the build
    platform.  You can explicitly set such a compiler with configure
    arguments. On HP/UX you might want to try: "CC_FOR_BUILD=c89".



    Specific problems on some machines
    ----------------------------------

    * Apple Darwin 6.1:

        ./configure --with-libiconv-prefix=/sw

    * IBM RS/6000 running AIX:

	Due to a change in gcc (since version 2.8) the MPI stuff may
	not build. In this case try to run configure using:
	    CFLAGS="-g -O2 -mcpu=powerpc" ./configure

    * SVR4.2 (ESIX V4.2 cc)

        Due to problems with the ESIX as, you probably want to do
            CFLAGS="-O -K pentium" ./configure --disable-asm

    * SunOS 4.1.4

         ./configure ac_cv_sys_symbol_underscore=yes


    The Random Device
    -----------------

    Random devices are available in Linux, FreeBSD and OpenBSD.
    Operating systems without a random devices must use another
    entropy collector. 

    This collector works by running a lot of commands that yield more
    or less unpredictable output and feds this as entropy into the
    random generator - It should work reliably but you should check
    whether it produces good output for your version of Unix. There
    are some debug options to help you (see cipher/rndunix.c).


    Creating an RPM package
    -----------------------

    The file scripts/gnupg.spec is used to build a RPM package (both
    binary and src):
      1. copy the spec file into /usr/src/redhat/SPECS
      2. copy the tar file into /usr/src/redhat/SOURCES
      3. type: rpm -ba SPECS/gnupg.spec

    Or use the -t (--tarbuild) option of rpm:
      1. rpm -ta gnupg-x.x.x.tar.gz

    The binary rpm file can now be found in /usr/src/redhat/RPMS, source
    rpm in /usr/src/redhat/SRPMS


    Building Universal Binaries on Apple OS X
    -----------------------------------------

    You can build a universal ("fat") binary that will work on both
    PPC and Intel Macs with something like:

    ./configure CFLAGS="-arch ppc -arch i386" --disable-endian-check \
		--disable-dependency-tracking --disable-asm

    If you are doing the build on a OS X 10.4 (Tiger) PPC machine you
    may need to add "-isysroot /Developer/SDKs/MacOSX10.4u.sdk" to
    those CFLAGS.  This additional isysroot is not necessary on Intel
    Tiger boxes, or any OS X 10.5 (Leopard) or later boxes.

    Note that when building a universal binary, any third-party
    libraries you may link with need to be universal as well.  All
    Apple-supplied libraries (even libraries not originally written by
    Apple like curl, zip, and BZ2) are universal.


    GnuPG 1.4 and GnuPG 2.0
    -----------------------

    GnuPG 2.0 is a newer version of GnuPG with additional support for
    S/MIME.  It has a different design philosophy that splits
    functionality up into several modules.  Both versions may be
    installed simultaneously without any conflict (gpg is called gpg2
    in GnuPG 2).  In fact, the gpg version from GnuPG 1.4 is able to
    make use of the gpg-agent as included in GnuPG 2 and allows for
    seamless passphrase caching.  The advantage of GnupG 1.4 is its
    smaller size and no dependency on other modules at run and build
    time.


    How to Get More Information
    ---------------------------

    The primary WWW page is "http://www.gnupg.org"
    The primary FTP site is "ftp://ftp.gnupg.org/gcrypt/"

    See http://www.gnupg.org/download/mirrors.html for a list of
    mirrors and use them if possible.  You may also find GnuPG
    mirrored on some of the regular GNU mirrors.

    We have some mailing lists dedicated to GnuPG:

	gnupg-announce@gnupg.org    For important announcements like
				    new versions and such stuff.
				    This is a moderated list and has
				    very low traffic.  Do not post to
				    this list.

	gnupg-users@gnupg.org	    For general user discussion and
				    help (English).

        gnupg-de@gnupg.org          German speaking counterpart of
                                    gnupg-users.

        gnupg-ru@gnupg.org          Russian speaking counterpart of
                                    gnupg-users.

	gnupg-devel@gnupg.org	    GnuPG developers main forum.

    You subscribe to one of the list by sending mail with a subject
    of "subscribe" to x-request@gnupg.org, where x is the name of the
    mailing list (gnupg-announce, gnupg-users, etc.).  An archive of
    the mailing lists are available at
    http://www.gnupg.org/documentation/mailing-lists.html

    Please direct bug reports to http://bugs.gnupg.org or post
    them direct to the mailing list <gnupg-devel@gnupg.org>.

    Please direct questions about GnuPG to the users mailing list or
    one of the pgp newsgroups; please do not direct questions to one
    of the authors directly as we are busy working on improvements and
    bug fixes.  The English and German mailing lists are watched by
    the authors and we try to answer questions when time allows us to
    do so.

    Commercial grade support for GnuPG is available; please see
    http://www.gnupg.org/service.html .
