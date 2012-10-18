===========================================================
cafdec - CAF decoder using Apple CoreAudioToolbox for win32
===========================================================

Usage: cafdec INFILE [OUTFILE]

"-" as OUTFILE means stdout.
When OUTFILE is not specified, output filename is automatically chosen
with a extension ".wav".

Note
----
1. AAC/MP3 in CAF is decoded into 32bit float format.
2. Decoding of HE-AACv2 is not supported.
3. Delay and padding are taken care of (removed), when they are described in
   packet table chunk header.

How to build
------------
You need Microsoft Visual C++ 2010 to build cafdec.
