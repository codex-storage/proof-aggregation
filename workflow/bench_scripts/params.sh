#!/bin/bash

export MAXDEPTH=32        # maximum depth of the slot tree
export MAXSLOTS=256       # maximum number of slots
export CELLSIZE=2048      # cell size in bytes
export BLOCKSIZE=65536    # block size in bytes
export NSAMPLES=100         # number of samples to prove

export ENTROPY=1234567    # external randomness
export SEED=12345         # seed for creating fake data

export NSLOTS=11          # number of slots in the dataset
export SLOTINDEX=3        # which slot we prove (0..NSLOTS-1)
export NCELLS=512         # number of cells in this slot