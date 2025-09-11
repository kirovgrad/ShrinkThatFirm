# ShrinkThatFirm

## Features

A Python tool for analyzing a firmware file system in order to shrink it:
- Find duplicated files;
- Find duplicated functions throughout binaries in filesystem;
- Find unused shared libraries (not 100% probability of unused);
- Find unused executable service binaries (not 100% probability of unused);
- Find unused functions throughtout binaries in filesystem (there are some snags);

The first 4 type of waste may be found running **main.py** file. 
For finding unused functions you have to run **unused_funcs_finder.py**, which uses idalib, which is available only in **IDA Pro 9** and later.
You can also run **ida_unused_funcs_script.py** as an idapython script right in IDA Pro itself, but before that in **ida_unused_funcs_script.py**:
1) Comment lines 330 and 331;
2) Comment lines from 358 to 364 and print the result of **unneeded_funcs** list.

Script for searching unused functions is mostly suitable for binaries written in C. If some function in its sources is called with PRIVATE flag, it might be falsly identified as unused and all functions inside of it also. 
Also, most compilers inline small functions, so they also might be falsly considered unused. You can uncomment filtering function and change the edge of minimum functions size as you wish. By default it is 140 bytes.

## Usage

```bash
python ShrinkThatFirm/main.py <fsdir> <numOfThreads>
```

### Arguments
* `fsdir`:Path to the extracted firmware filesystem.
* `numOfThreads`:Number of threads by which the script will search through filesystem.

## Requirements

- Python 3.6+
- `r2pipe`
- IDA Pro 9>
