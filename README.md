# CSED312 Pintos project

Run `sudo apt-get install binutils pkg-config zlib1g-dev libglib2.0-dev gcc libc6-dev autoconf libtool libsdl1.2-dev g++ libx11-dev libxrandr-dev libxi-dev perl libc6-dbg gdb make git qemu ctags`

## Setup for project 1

1. Open `src/utils/pintos-gdb`, change line 4 to `GDBMACROS=$PINTOS_ROOT/src/misc/gdb-macros`. Expand `$PINTOS_ROOT` to actual path.
2. Open `src/threads/Make.vars`, change line 7 to `SIMULATOR = --qemu`.
3. Open `src/utils/pintos`, change `kernel.bin` on line 257 to `$PINTOS_ROOT/src/threads/build/kernel.bin`. Expand `$PINTOS_ROOT` to actual path.

4. Open `src/utils/Pintos.pm`, change `loader.bin` on line 362 to `$PINTOS_ROOT/src/threads/build/loader.bin`. Expand `$PINTOS_ROOT` to actual path.

5. Open `~/.bashrc` , add `export PATH=$PINTOS_ROOT/src/utils:$PATH` to a new line at the end. Expand `$PINTOS_ROOT` to actual path. Restart terminal.
6. Run `make` on two places: `src/utils` and `src/threads`. 

7. Move to `src/threads/build/`, check if `pintos --qemu -- run alarm-multiple` runs correctly.

## Setup for project 2

1. Do every setup from project 1.
2. Open `src/utils/pintos`, change `kernel.bin` on line 257 to `$PINTOS_ROOT/src/userprog/build/kernel.bin`. Expand `$PINTOS_ROOT` to actual path.
3. Open `src/utils/Pintos.pm`, change `loader.bin` on line 362 to `$PINTOS_ROOT/src/userprog/build/loader.bin`. Expand `$PINTOS_ROOT` to actual path.
