# Hash Extender by Ron Bowes <ron@skullsecurity.net>

This will be a blog post on http://www.skullsecurity.org/. For now, it's a README file.

## Intro

**You can grab the hash_extender tool on [Github](https://github.com/iagox86/hash_extender)!**

Awhile back, my friend [mogigoma](http://twitter.com/mogigoma) and I were doing a capture-the-flag contest at [https://stripe-ctf.com](https://stripe-ctf.com). One of the levels of the contest required us to perform a hash length extension attack. I had never even heard of the attack at the time, and after some reading I realized that not only is it a super cool (and conceptually easy!) attack to perform, there is also a total lack of good tools for performing said attack!  After hours of adding the wrong number of null bytes or incorrectly adding length values, I vowed to write a tool to make this easy for myself and anybody else who's trying to do it. So, after a couple weeks of work, here it is!

Now I'm gonna release the tool, and hope I didn't totally miss a good tool that does the same thing! It's called `hash_extender`, and implements a length extension attack against every algorithm I could think of:

- MD4
- MD5
- RIPEMD-160
- SHA-0
- SHA-1
- SHA-256
- SHA-512
- WHIRLPOOL

I'm more than happy to extend this to cover other hashing algorithms as well, provided they are "vulnerable" to this attack -- MD2, SHA-224, and SHA-384 are not. Please contact me if you have other candidates and I'll add them ASAP!

## The attack

An application is susceptible to a hash length extension attack if it prepends a secret value to a string, hashes it with a vulnerable algorithm, and entrusts the attacker with both the string and the hash, but not the secret.  Then, the server relies on the secret to decide whether or not the data returned later is the same as the original data.

It turns out, even though the attacker doesn't know the value of the prepended secret, he can still generate a valid hash for `{secret || data || attacker_controlled_data}`! This is done by simply picking up where the hashing algorithm left off; it turns out, 100% of the state needed to continue a hash is in the output of most hashing algorithms! We simply load that state into the appropriate hash structure and continue hashing.

**TL;DR: given a hash that is composed of a string with an unknown prefix, an attacker can append to the string and produce a new hash that still has the unknown prefix.**

## Example

Let's look at a step-by-step example. For this example:

- let `secret    = "secret"`
- let `data      = "data"`
- let `H         = md5()`
- let `signature = hash(secret || data) = 6036708eba0d11f6ef52ad44e8b74d5b`
- let `append    = "append"`

The server sends `data` and `signature` to the attacker. The attacker guesses that `H` is MD5 simply by its length (it's the most common 128-bit hashing algorithm), based on the source, or the application's specs, or any way they are able to.

Knowing only `data`, `H`, and `signature`, the attacker's goal is to append `append` to `data` and generate a valid signature for the new data. And that's easy to do! Let's see how.

### Padding

Before we look at the actual attack, we have to talk a little about padding.

When calculating `H`(`secret` + `data`), the string (`secret` + `data`) is padded with a '1' bit and some number of '0' bits, followed by the length of the string. That is, in hex, the padding is a 0x80 byte followed by some number of 0x00 bytes and then the length. The number of 0x00 bytes, the number of bytes reserved for the length, and the way the length is encoded, depends on the particular algorithm and blocksize.

With most algorithms (including MD4, MD5, RIPEMD-160, SHA-0, SHA-1, and SHA-256), the string is padded until its length is congruent to 56 bytes (mod 64). Or, to put it another way, it's padded until the length is 8 bytes less than a full (64-byte) block (the 8 bytes being size of the encoded length field). There are two hashes implemented in hash_extender that don't use these values: SHA-512 uses a 128-byte blocksize and reserves 16 bytes for the length field, and WHIRLPOOL uses a 64-byte blocksize and reserves 32 bytes for the length field.

The endianness of the length field is also important. MD4, MD5, and RIPEMD-160 are little-endian, whereas the SHA family and WHIRLPOOL are big-endian. Trust me, that distinction cost me days of work!

In our example, `length(secret || data) = length("secretdata")` is 10 (0x0a) bytes, or 80 (0x50) bits. So, we have 10 bytes of data (`"secretdata"`), 46 bytes of padding (80 00 00 ...), and an 8-byte little-endian length field (50 00 00 00 00 00 00 00), for a total of 64 bytes (or one block). Put together, it looks like this:

    0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......

Breaking down the string, we have:

- `"secret" = secret`
- `"data" = data`
- 80 00 00 ... -- The 46 bytes of padding, starting with 0x80
- 50 00 00 00 00 00 00 00 -- The bit length in little endian

This is the exact data that `H` hashed in the original example.

### The attack

Now that we have the data that `H` hashes, let's look at how to perform the actual attack.

First, let's just append `append` to the string. Easy enough!  Here's what it looks like:

    0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
    0040  61 70 70 65 6e 64                                append

The hash of that block is what we ultimately want to a) calculate, and b) get the server to calculate. The value of that block of data can be calculated in two ways:

- By sticking it in a buffer and performing `H(buffer)`
- By starting at the end of the first block, using the state we already know from `signature`, and hashing `append` starting from that state

The first method is what the server will do, and the second is what the attacker will do. Let's look at the server, first, since it's the easier example.

#### Server's calculation

We know the server will prepend `secret` to the string, so we send it the string minus the `secret` value:

    0000  64 61 74 61 80 00 00 00 00 00 00 00 00 00 00 00  data............
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 50 00 00 00 00 00 00 00 61 70 70 65 6e 64  ..P.......append

Don't be fooled by this being exactly 64 bytes (the blocksize) -- that's only happening because `secret` and `append` are the same length. Perhaps I shouldn't have chosen that as an example, but I'm not gonna start over!

The server will prepend `secret` to that string, creating:

    0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
    0040  61 70 70 65 6e 64                                append

And hashes it to the following value:

    6ee582a1669ce442f3719c47430dadee

For those of you playing along at home, you can prove this works by copying and pasting this into a terminal:

    echo '
    #include <stdio.h>
    #include <openssl/md5.h>
  
    int main(int argc, const char *argv[])
    {
      MD5_CTX c;
      unsigned char buffer[MD5_DIGEST_LENGTH];
      int i;
  
      MD5_Init(&c);
      MD5_Update(&c, "secret", 6);
      MD5_Update(&c, "data"
                     "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00"
                     "\x50\x00\x00\x00\x00\x00\x00\x00"
                     "append", 64);
      MD5_Final(buffer, &c);
  
      for (i = 0; i < 16; i++) {
        printf("%02x", buffer[i]);
      }
      printf("\n");
      return 0;
    }' > hash_extension_1.c
  
    gcc -o hash_extension_1 hash_extension_1.c -lssl -lcrypto
  
    ./hash_extension_1

All right, so the server is going to be checking the data we send against the signature `6ee582a1669ce442f3719c47430dadee`. Now, as the attacker, we need to figure out how to generate that signature!

#### Client's calculation

So, how do we calculate the hash of the data shown above without actually having access to `secret`?

Well, first, we need to look at what we have to work with: `data`, `append`, `H`, and `H(secret || data)`.

We need to define a new function, `H'`, which uses the same hashing algorithm as `H`, but whose starting state is the final state of `H(secret || data)`, i.e., `signature`. Once we have that, we simply calculate `H'(append)` and the output of that function is our hash. It sounds easy (and is!); have a look at this code:

    echo '
    #include <stdio.h>
    #include <openssl/md5.h>
  
    int main(int argc, const char *argv[])
    {
      int i;
      unsigned char buffer[MD5_DIGEST_LENGTH];
      MD5_CTX c;
  
      MD5_Init(&c);
      MD5_Update(&c, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64);
  
      c.A = htonl(0x6036708e); /* <-- This is the hash we already had */
      c.B = htonl(0xba0d11f6);
      c.C = htonl(0xef52ad44);
      c.D = htonl(0xe8b74d5b);
  
      MD5_Update(&c, "append", 6); /* This is the appended data. */
      MD5_Final(buffer, &c);
      for (i = 0; i < 16; i++) {
        printf("%02x", buffer[i]);
      }
      printf("\n");
      return 0;
    }' > hash_extension_2.c
  
    gcc -o hash_extension_2 hash_extension_2.c -lssl -lcrypto
  
    ./hash_extension_2

The the output is, just like before:

    6ee582a1669ce442f3719c47430dadee

So we know the signature is right. The difference is, we didn't use `secret` at all! What's happening!?

Well, we create a `MD5_CTX` structure from scratch, just like normal.  Then we take the MD5 of 64 'A's. We take the MD5 of a full (64-byte) block of 'A's to ensure that any internal values -- other than the state of the hash itself -- are set to what we expect.

Then, after that is done, we replace `c.A`, `c.B`, `c.C`, and `c.D` with the values that were found in `signature`: `6036708eba0d11f6ef52ad44e8b74d5b`. This puts the MD5_CTX structure in the same state as it finished in originally, and means that anything else we hash -- in this case `append` -- will produce the same output as it would have had we hashed it the usual way.

We use `htonl()` on the values before setting the state variables because MD5 -- being little-endian -- outputs its values in little-endian as well.

#### Result

So, now we have this string:

    0000  64 61 74 61 80 00 00 00 00 00 00 00 00 00 00 00  data............
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 50 00 00 00 00 00 00 00 61 70 70 65 6e 64  ..P.......append

And this signature for `H(secret || data || append)`:

   6ee582a1669ce442f3719c47430dadee

And we can generate the signature without ever knowing what the secret was!  So, we send the string to the server along with our new signature. The server will prepend the signature, hash it, and come up with the exact same hash we did (victory!).

## The tool

**You can grab the hash_extender tool on [Github](https://github.com/iagox86/hash_extender)!**

This example took me hours to write. Why? Because I made about a thousand mistakes writing the code. Too many NUL bytes, not enough NUL bytes, wrong endianness, wrong algorithm, used bytes instead of bits for the length, and all sorts of other stupid problems. The first time I worked on this type of attack, I spent from 2300h till 0700h trying to get it working, and didn't figure it out till after sleeping (and with Mak's help). And don't even get me started on how long it took to port this attack to MD5. Endianness can die in a fire.

Why is it so difficult? Because this is crypto, and crypto is `immensely` complicated and notoriously difficult to troubleshoot. There are lots of moving parts, lots of side cases to remember, and it's never clear why something is wrong, just that the result isn't right. What a pain!

So, I wrote hash_extender. hash_extender is (I hope) the first free tool that implements this type of attack. It's easy to use and implements this attack for every algorithm I could think of.

Here's an example of its use:

    $ ./hash_extender --data data --secret 6 --append append --signature 6036708eba0d11f6ef52ad44e8b74d5b --format md5
    Type: md5
    Secret length: 6
    New signature: 6ee582a1669ce442f3719c47430dadee
    New string: 64617461800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000617070656e64

If you're unsure about the hash type, you can let it try different types by leaving off the --format argument. I recommend using the --table argument as well if you're trying multiple algorithms:

    $ ./hash_extender --data data --secret 6 --append append --signature 6036708eba0d11f6ef52ad44e8b74d5b --out-data-format html --table
    md4       89df68618821cd4c50dfccd57c79815b data80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000P00000000000000append
    md5       6ee582a1669ce442f3719c47430dadee data80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000P00000000000000append

There are plenty of options for how you format inputs and outputs, including HTML (where you use `%NN` notation), CString (where you use `\xNN` notation, as well as `\r`, `\n`, `\t`, etc.), hex (such as how the hashes were specified above), etc.

By default I tried to choose what I felt were the most reasonable options:

- Input data: raw
- Input hash: hex
- Output data: hex
- Output hash: hex

Here's the help page for reference:

    --------------------------------------------------------------------------------
    HASH EXTENDER
    --------------------------------------------------------------------------------
    
    By Ron Bowes <ron @ skullsecurity.net>
    
    See LICENSE.txt for license information.
    
    Usage: ./hash_extender <--data=<data>|--file=<file>> --signature=<signature> --format=<format> [options]
    
    INPUT OPTIONS
    -d --data=<data>
          The original string that we're going to extend.
    --data-format=<format>
          The format the string is being passed in as. Default: raw.
          Valid formats: raw, hex, html, cstr
    --file=<file>
          As an alternative to specifying a string, this reads the original string
          as a file.
    -s --signature=<sig>
          The original signature.
    --signature-format=<format>
          The format the signature is being passed in as. Default: hex.
          Valid formats: raw, hex, html, cstr
    -a --append=<data>
          The data to append to the string. Default: raw.
    --append-format=<format>
          Valid formats: raw, hex, html, cstr
    -f --format=<all|format> [REQUIRED]
          The hash_type of the signature. This can be given multiple times if you
          want to try multiple signatures. 'all' will base the chosen types off
          the size of the signature and use the hash(es) that make sense.
          Valid types: md4, md5, ripemd160, sha, sha1, sha256, sha512, whirlpool
    -l --secret=<length>
          The length of the secret, if known. Default: 8.
    --secret-min=<min>
    --secret-max=<max>
          Try different secret lengths (both options are required)
    
    OUTPUT OPTIONS
    --table
          Output the string in a table format.
    --out-data-format=<format>
          Output data format.
          Valid formats: none, raw, hex, html, html-pure, cstr, cstr-pure, fancy
    --out-signature-format=<format>
          Output signature format.
          Valid formats: none, raw, hex, html, html-pure, cstr, cstr-pure, fancy
    
    OTHER OPTIONS
    -h --help 
          Display the usage (this).
    --test
          Run the test suite.
    -q --quiet
          Only output what's absolutely necessary (the output string and the
          signature)

## Defense

So, as a programmer, how do you solve this? It's actually pretty simple. There are two ways:

- Don't trust a user with encrypted data or signatures, if you can avoid it.
- If you can't avoid it, then use HMAC instead of trying to do it yourself.  HMAC is `designed` for this.

HMAC is the real solution. HMAC is designed for securely hashing data with a secret key.

As usual, use constructs designed for what you're doing rather than doing it yourself. The key to all crypto! [pun intended]

**And finally, you can grab the hash_extender tool on [Github](https://github.com/iagox86/hash_extender)!**

/hash_extender --file download.zip --secret 16 --append 504b03041403000008001cbd9753c7297141a5090000a03f00000c0000006d6f765f66696c652e62696eed5b67a8134110de3b5b6c31f6aeb1373c63ef256af49467ef58ce684e8da6915cec621783f5878208820d1b088a20fe103b3650545044113b46b1f71e672f735c76f55410d11ff7c9e6bbf97666b6dce6bd3c7333d797d743140462201fe944a8b5da95b5bba0ee6ea3136a6d485178ad46aa928260e7cff1e37992c8b2c31807e376a0ce7315c2b26032c459635e419689cb8c2b9063f33c5a6418746e3c37ea1c4f174ce6e3e814d28da905dcd160763f9672e38918f71ee3de7764f9966030bb9ff9b19dc07c3c77272ce747ee7f5f0bd06b0fae87e70e04998b1b007105c9efc3853c10c7b3da970a22cbc6b6360905c7b56ad12414681c0a4692d31b4f6fd3aa71ab1652222a35d3e75406cf54cfbe4348b9f315b6b65fbb4cfab26c6c9dc95bdf0ca877a3caa6fc3807017d08faebc3201731ef1b5cccd765aa158576513d1f6efb725915628131782478548456ea077a310bbdb485deca429f69316e410bff9485bf60e15f0f5a4d5ec41c25617563bbb0e7904c54b5f1644234a646482c1e8c6813c88458924ae343d1844a125a408dc789a28c9fee57260423fe5070a60a26dcdef14a42f3c73525ec0f4608b5e9dd6d457ae6f5eada4d692635935a12a5d7e03e0a24502706139a1a1fdca75b281a5107fbc785688e89e16804732859d71f3aeaab15f11fbd420bf7412072ce794d560a1626d0379018e7945d6fac64969f73ba0775d9dc1fc6bedad9bc4f0231712b472f90a3a74d1d9a89e739ba23477f9fa31731e5ecfdc2dc4573f40aa817c2f78201778e9e2f47af6fe8dccf638fa94333d126472f4c6cd8b061c3860d1b366cfc2bc80b1f3be465056e3481cbc547343173415e78c2719c18c8b4bc035d993af7e0b544f52e7045ed4904f0f0560650e71ab5056a5fd0ed4bd416a97d44b7cf523b1fb5f7e8f6316ae7a7f646dd8e833d613541347dd22b75718c9cba232fbcf7bcffe0bc150576416e7945f16e3a753c4ae754b62ec4bc2e51bdbb2ea59a502ab08052dbf75a5958ce5729bb9cc2995b25aacf2380e3c8e03f42f76f39905283af72eab97cf46967f9e8fb7cb27052bef8552b03092e630247e6d60418c78c9fd7b16913a0649321f2c28efb259a31755f2b262febf8118c746358517a12bc9c2c5018fc84d1469cc10f6741e71088818d77c12ce639f539cd024a5ff89ac9c829df7b79e19cf7245912e50304905e43fb96415fea54fa005c2ff5bd2b71c8f74e5e5676bd44e77005f479a0cf9bf32e93bc6278f605458f3f638cef1d96b7a2e3b3467031b457ea8a7748afd41bef606feaf3107945e35b200fca6bf0859e89f4dd2f30e0d12ff9b4ca4daf97a84ef2522ff3524fbba71e7833656eca0b8f0b72db1bc947f4ac8c1ced1de51ded1de355600c721ccf54f614d9b061c3860d1b366cd8b061c3868dff050211499c3499ea8f3749c4a2d15013fd4b3b352e85a21349916edebe7dfb0d76f7ebefebebeed12bcf07fe95f3b5ef80df2b3d7f067f8702f77f9ec9ec011e0b3c1cd8f72293390d7c04380dec7e99c97804a2a38c31eecc814498ee122a172be4582d147251bd0a01408e46e863ed4f486df41f0b73184b004e570f6785de258a4e73cc239d2bb56fd8bc764d23be3bb475e0e720088c1d052d09e36954f03a5d4bc46ec50b8a5118211b331bda05e81f4d005d9dae55622f678595f97c4ef78afc3e67fde505ba3b3d4b0acace360b0bf5747699ec6ce3757abccefa5d9deeaece0ae0dfd5e9d0bf473c012d0d790462c3860d1b366cd8b061c3860d1b7f1fc6738a1e64017519b918f7a06e71340797ca7245eef9c7ca683b902b11f639c82a5cff9baf99a86ee7c3e70f51ef9f3fcb05d1f6607f11b4b7201745ae805c96b08030e6c17311cde9dcdf918590cb233b0ab2baa7003befabc885b9f13f65e87a4cd7af68bb303e83b660ec0bdaaf71bd1fd0ce47fe2dde77fcb1de0acf410fe4a1c81390a72213eeb9d69eddbab573d7efae8e0bfa23eea61ea9b9e469dcb46903bc2456c0e7ec5f6478bdb0de978fa445f6f1fbd216fed5f47bef2447b8f9b9517fcee9cd51f79464f55efab815c9a42eecfb65887e5d06cfb989d99827c6e5594afd61b669ce7fbbc5fcadd6b54fcf538a6835b80e0bffa3988d9fe7253d4fd9efeefb75f4e7e7f9945094c47a001382008dbe8bbab0fa1dd045fa6ee5f6b93ce8a5607ffa9762f7b39e80f794c3665daf40ba70f9bb81ee02bd3fa7f7d6f37f8f1a54174b90c15ce7680bff9885bec042df88f3e1e7b9db625d07412f29562032e77f86eac405416c9dc555dcb7e72571dea89f83e682f319e3f26c437fa37ea711ea6921ebcfefdb6bf44f627e0df50f16eb2d2a66e7cfe7292ffe78bd4dc51fd70fe4893fce3f5ab4a82b18343eae3595a24451fce3828ae69f48404868c90913a4f1c42c0950b4b0329e3eeb9f00cf405499188a8ef3879480168d27147f723a191f0dc742aaa60624cf8f3d68554250f1c7e3fe198a1ad1e233c884b83fac2a8164383c0342722c053c35c6351c9daa4282902a8d07d71e03bd7d7c8aaf6f775a8fc03a0788d27d445f6f9f5eddd81ebd7c0124a851517c326690bb0f244acfbc7e5dbd794abf1e3d06f9062b83bd5df37c8a5138313e91d4a7fdf3020935e0d7fc5888d125a7ac020b3518492fda6094ef6a34b85e9a3cdbcb9762405f22aa4cf247027416bdfa414720185192093590bb00ba0b608f4b24300d1d442f25e1878265e1ae5a56797015264c82892abb342c4a61242225668435ff38602d9ee549c695fe1fe4312245a29a2a4d8c24a571c920142605032879bbf66a4c0fa8de37c99f9844a4c08c08e4d319b2647ba6aaf144301a610c05fae26ac84f1df12a16d288a4ef0dbd942646e14253a7c32bbde3e014d56faba44ec2a3392910372d2299872b1b81d774047f38389ed08cd941b27960ff8904ef92309c68f2c7a88c3feb456255e7c742e0ec5a5c4d0a5fd7569bff5dc8d9adb8f8b4c8b2fb17f1dda1bd85cf6a46bc231fcbf5512f60f473f17df1b3ab687ebe65d82db075400eee73e650ae4ead7f7e96b7fc62ffc640cbe0fcf1f327c315b8f98b1c4fc1cfb686ed2ac0b29b70f3ff417d5afedcf51760f92a373ebffe4518dfd5e82fc8f2f49cf8f23f885f69d6f4fdb0eeb3fc2fee7f8a8b77bb581ecbf9bb385ec3c5cf73b1ccef9783e30d5cfc6a17cb47057e7c165bb8f8c1a5582efc8bf5efe4debf7cfd6b935fc4ef65e2adea4bade30f73f13137cb0e81df3f1667a039f13dc4d49b36febdfdbf0cad444efcf38ec8bf197f1bf71ee2d97adec66c1d6f412ece85bc0ed70ff15837888c1b5fff17e33f32e3d9c26c0f635ac6bfe2e2bb7441f630f3b4dcff0fa8e5e3ea0ffb5bc4bb39fb2b8e0fee0836be3aa70b3ce3d9e111c3f836f9cddf43657ff0f3a330ce9dc78e169847e4c76751d222be42eb2c17127e1eff0d504b01023f031403000008001cbd9753c7297141a5090000a03f00000c0024000000000000002080ed81000000006d6f765f66696c652e62696e0a002000000000000100180000bca37080f8d70100bca37080f8d70100bca37080f8d701504b050600000000010001005e000000cf0900000000 --signature 2bab052bf894ea1a255886fde202f451476faba7b941439df629fdeb1ff0dc97 -f sha256 --out-data-format hex

Troll_Pay_Chart