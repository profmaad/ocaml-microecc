ocaml-microecc
==============

OCaml bindings for the micro-ecc ECC library

Dependencies
============

This project uses OASIS as its build system and the micro-ecc library by Kenneth MacKay (https://github.com/kmackay/micro-ecc).

Building & Installation
=======================

After cloning the repository, perform the following to build the library:

```
git submodule init
git submodule update
oasis setup
./configure --enable-tests
make test
```

If you don't want to run tests, you can leave out the call to ```./configure``` and just run ```make``` instead of ```make test```.

To install the library using OPAM:
```
make install
```

Please note that the build system is currently not really ready for primetime and uses a very awkward way to inject the "stub" library into OPAM.
As it happens, the stub library is also not "stubby" at all but actually contains the entire micro-ecc code... oh well.
