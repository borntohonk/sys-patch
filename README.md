# sys-patch

A script-like system module that patches **fs** on boot.

---

## Building

### prerequisites
- Install [devkitpro](https://devkitpro.org/wiki/Getting_Started)
- Run the following:
  ```sh
  git clone --recurse-submodules https://github.com/ITotalJustice/sys-patch.git
  cd ./sys-patch
  make
  ```

The output of `out/` can be copied to your SD card. (it shouldn't be, as this version is for embedding into atmospheres stratosphere.romfs)
To activate the sys-module, reboot your switch

---

## What is being patched?

Here's a quick run down of what's being patched:

- **fs** need new patches after every new firmware version.
The patches are applied on boot. Once done, the sys-module stops running.
The memory footprint *(16kib)* and the binary size *(~50kib)* are both very small.

---

## Credits / Thanks

Software is built on the shoulders of giants. This tool wouldn't be possible without these people:

- BornToHonk (farni)
- Switchbrew (libnx, switch-examples)
- DevkitPro (toolchain)
- N
