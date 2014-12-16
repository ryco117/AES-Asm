README
======

This is a simple demonstration of the ASE-NI instructions in use in assembly, distributed under the GNU GPL V3 License.
It is mostly a proof of concept piece, and is heavily commented for easy readability. It can be easily called from C++ for
greater ease of use. This is specifically designed for Linux 64bit. To build for another environment, one would need to consider
the way in which C++ will pass arguments in this environment and that the use of registers xmm8 (which is used once because laziness)
and r8 are only available is 64bit (as well as change all general registers to 32 bit)