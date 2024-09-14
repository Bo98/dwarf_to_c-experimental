Very rudimentary DWARF to C converter. Shared largely for only a couple people.

Don't expect valid C code. It's very much best effort and only tested on a very small number of files, largely from older DWARF versions.

It will probably crash on anything I haven't tested on, it requires configuring a JSON to work and it is very slow and RAM hungry (at least 32GB recommended, maybe even 64GB for some files).

If you are wanting to extract specific structures I recommend using another tool instead.
