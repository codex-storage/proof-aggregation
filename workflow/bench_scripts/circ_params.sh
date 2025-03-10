#!/bin/bash

export MAX_DEPTH=32                # maximum depth of the slot tree
export MAX_LOG2_N_SLOTS=8          # Depth of the dataset tree = ceiling_log2(max_slots)
export BLOCK_TREE_DEPTH=5          # depth of the mini tree (block tree)
export N_FIELD_ELEMS_PER_CELL=272  # number of field elements per cell
export N_SAMPLES=100                 # number of samples to prove