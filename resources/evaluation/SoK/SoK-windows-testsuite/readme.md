(fetch the contents of this directory from: [here](https://drive.google.com/file/d/1KEYthnC5T_GcJGUxdw73zmUmGHJI3n56/view?usp=sharing). reproducing the embedded readme here.)

# SoK Windows Testsuite for Disassembly Analysis

This is a collection of Windows PE files,
 their debugging program databases (.pdb),
 and code layout ground truth as computed by [SoK](https://github.com/junxzm1990/x86-sok).

First, references:
  - the paper ["SoK: All You Ever Wanted to Know About x86/x64Binary Disassembly But Were Afraid to Ask"](https://arxiv.org/ftp/arxiv/papers/2007/2007.14266.pdf)
  - the source code [github/junxzm1990/x86-sok](https://github.com/junxzm1990/x86-sok)
  - the test suite [gdrive link](https://drive.google.com/file/d/1Jd1O9eVIeFasOcuQjLcIxFswzKXuK6A8/view?usp=sharing)

I took the Windows binaries from the test suite and used the SoK tools to extract the ground truth data.
This verbatim output is found in the `*.gt.ref.pb.gz` and `*.gt.block.pb.gz` gzipped ProtoBuf files.
(ProtoBuf definitions:
 [refInf.proto](https://raw.githubusercontent.com/junxzm1990/x86-sok/d4c1e3b9e98cff4c3a5db0180c135f393449c61e/protobuf_def/refInf.proto)
 and
 [blocks.proto](https://raw.githubusercontent.com/junxzm1990/x86-sok/d4c1e3b9e98cff4c3a5db0180c135f393449c61e/protobuf_def/blocks.proto))
For ease of use, I also translated the ProtoBuf data into gzipped JSON documents that can be found in `*.gt.json.gz`.


---

#### notes for rebuilding this

- https://arxiv.org/abs/2007.14266
- [testsuite](https://drive.google.com/file/d/1Jd1O9eVIeFasOcuQjLcIxFswzKXuK6A8/view?usp=sharing)
- https://github.com/junxzm1990/x86-sok
  - [blocks.proto](https://raw.githubusercontent.com/junxzm1990/x86-sok/d4c1e3b9e98cff4c3a5db0180c135f393449c61e/protobuf_def/blocks.proto)
  - [refInf.proto](https://raw.githubusercontent.com/junxzm1990/x86-sok/d4c1e3b9e98cff4c3a5db0180c135f393449c61e/protobuf_def/refInf.proto)
  - [blocks_pb2.py](https://raw.githubusercontent.com/junxzm1990/x86-sok/d4c1e3b9e98cff4c3a5db0180c135f393449c61e/protobuf_def/blocks_pb2.py)
  - [refInf_pb2.py](https://raw.githubusercontent.com/junxzm1990/x86-sok/d4c1e3b9e98cff4c3a5db0180c135f393449c61e/protobuf_def/refInf_pb2.py)
- [cvdump.exe](https://github.com/microsoft/microsoft-pdb/raw/master/cvdump/cvdump.exe)
- `dumpbin.exe` found in a location like: `C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/VC/Tools/MSVC/14.24.28314/bin/Hostx64/x64/dumpbin.exe`

To build `PEMap`:
```sh
sudo apt install libiberty-dev libcapstone-dev libboost-dev libprotobuf-dev llvm-10-toolchain
sudo ln -s /usr/bin/llvm-readelf-10 /usr/local/bin/llvm-readelf
sudo ln -s /usr/bin/llvm-pdbutil-10 /usr/local/bin/llvm-pdbutil
make
```

To build the ground truth:

```sh
for F in $(find ./windows -name "*.pdb"); do
  BASE="${F%.*}";
  echo "$BASE";
  python ./dumpfixup.py -p "$BASE".pdb -b "$BASE".[ed]* -o "$BASE"_gtRef.pb > /dev/null 2>&1;
  ./PEMap -iwRFE -P "$BASE".pdb -r "$BASE"_gtRef.pb -e "$BASE".[ed]* -o "$BASE"_gtBlock.pb > /dev/null 2>&1;
done
```
