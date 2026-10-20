# MGS-MPO-Noesis
Noesis plugin for Metal Gear Solid: Portable Ops (MPO) and Metal Gear Solid: Portable Ops Plus (MPO+ / MPOP).

Supports archive extraction, models, textures, associated rigs and animation.

# Options (command line / advanced options):
-mpoanims <mode>     all (default: load every matching .mtar in the folder), none, or a comma separated list of .mtar file names to load

-mpomotions <list>   only load the listed motion indices (e.g. 0,2,5-7) from each .mtar

-mpoanimpath <path>  extra .mtar file or folder to take animations from (also settable from the Tools menu)

-mpoinplace          remove the horizontal root motion (the root height is kept)

-mponoroot           don't apply the root motion channel to the root bone at all

-mpokeepwinding      keep the original (arbitrary) triangle winding of double-sided geometry

-mpoarcraw           archive extraction: write nested .dar/.qar as files instead of unpacking them

-mpohexnames         archive extraction: always name slot.dat files by hash
