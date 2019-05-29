# How to Run

- Clone this repo
- Install [angr](https://github.com/angr/angr) using the directions [here](https://docs.angr.io/introductory-errata/install)
    - NOTE: currently only works with angr version 8.19.4.5 (latest in Pip as of this writing).
        - Actually, currently requires a small patch against angr; the patched version is available
        at [our fork of angr](https://github.com/cdisselkoen/angr) on its `more-hooks` branch.
    - It is highly recommended to use the [pypy](https://pypy.org) JITting Python interpreter
        rather than the standard Python interpreter. E.g., on Mac:
        ```bash
        brew install pypy3
        cd /path/to/where/you/cloned/this/repo
        pypy3 -m venv [whatever_you_want_to_name_your_virtualenv]
        source [your_virtualenv_name]/bin/activate
        ```
        then proceed with the standard angr installation using the pypy virtualenv. Inside this virtualenv, `python` should give you a pypy interpreter rather than an ordinary Python one.
    - This code has only been tested with PyPy 7.0-7.1 (both of which implement Python 3.6.1).
- Inside your Python virtualenv, run `python pitchfork.py` to run tests
against all the original Kocher test cases, our new Spectre v1 test cases,
and our Spectre v1.1 test cases (see below).
- Current status / explanations of expected Kocher test results is in [kocher_analysis.txt](kocher_analysis.txt)
- To run other tests or workloads, look at the functions in [pitchfork.py](pitchfork.py)
- Some useful utilities for interactive investigation are in [utils.py](utils.py) (imported with [pitchfork.py](pitchfork.py))

# Our new Spectre testcases

We have two sets of Spectre testcases:

- A revised version of the well-known Kocher testcases for Spectre v1.
The main difference in our revision is that unlike the original testcases,
our revised ones do not perform out-of-bounds or secret-dependent memory
accesses, or branch on secret data, when executed non-speculatively.
These cases are found in [new-testcases/spectrev1.c](new-testcases/spectrev1.c);
detailed explanations of changes can be found in comments in that file.

- A new set of testcases for Spectre v1.1.
Spectre v1.1 is similar to Spectre v1 except that it relies on an out-of-bounds
write rather than an out-of-bounds read.
Our testcases demonstrate a variety of ways that these vulnerabilities can appear.
They are found in [new-testcases/forwarding.c](new-testcases/forwarding.c);
detailed explanations of each of the cases can be found in comments in that file.
