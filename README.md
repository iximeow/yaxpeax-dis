## yaxpeax-dis

`yaxpeax-dis` is the repo providing `yaxdis`, a small and very naive disassembler to exercise decoders in the [yaxpeax project](https://git.iximeow.net/yaxpeax-arch/). it does not (currently?) do much other than disassembling hex input, and is mostly useful as an example of how to use decoders and spot-checking a specific instruction's decoding.

## usage

if you just want to build and use it, `cargo install yaxpeax-dis` should get you started. otherwise, clone this repo and a `cargo build` will work as well.

`yaxdis [-a arch] [hex bytes]`, such as `yaxdis -a x86_64 33c0c3` which should yield:
```
0x00000000: 33c0          : xor eax, eax
0x00000002: c3            : ret
```
or `yaxdis -a armv7 83591764ab46cd42`, producing:
```
0x00000000: 83591764      : ldrvs r5, [r7], #-0x260c
0x00000004: ab46cd42      : sbcmi sp, 0x46ab
```
or `yaxdis -a ia64 e38000000061e200000042c0e1803080`, producing:
```
0x00000000: e38000000061e200000042c0e1803080: [MII] (p07) mov r16=r0; (p09) mov r14=r0;; and r14=r14,r16;;
```

`yaxdis` also takes a `-v` flag to emit more verbose information (really, a `Debug` display of decoded instructions).

## supported architectures / ! user beware !
`yaxdis` should support all architectures listed in the [yaxpeax-arch readme](https://git.iximeow.net/yaxpeax-arch/). that is currently `x86_64`, `armv7`, `armv8`, `mips`, `msp430`, `pic17`, `pic18`, `m16c`, `avr`, and `ia64`. specific levels of support and stability vary, beware.
