# AES-EAX test vectors

`aes_eax_test.json` is vendored from [C2SP Project Wycheproof](https://github.com/C2SP/wycheproof),
file `testvectors_v1/aes_eax_test.json`, version 0.9. The vectors are
copyright Google and contributors and are distributed under the **Apache
License, Version 2.0**. The applicable license text is available at
<https://www.apache.org/licenses/LICENSE-2.0>.

The RFC-style vectors in the EAX tests are from M. Bellare, P. Rogaway, and
D. Wagner, *The EAX Mode of Operation*, ePrint 2003/069, Appendix G:
<https://eprint.iacr.org/2003/069>. The paper states that the EAX work is
placed in the **public domain** and is free and unencumbered for all uses.

These files are test inputs only; they are not linked into embedded library
builds.
