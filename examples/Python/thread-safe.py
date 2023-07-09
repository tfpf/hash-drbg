#! /usr/bin/env python3

import hdrbg

print(hdrbg.bytes(64).hex())

for _ in range(4):
    print(hdrbg.rand(), end=' ')
for _ in range(4):
    print(hdrbg.real(), end=' ')
print()
