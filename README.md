# What is Pitchfork?

Pitchfork is a static analysis tool, built on
[angr](https://github.com/angr/angr), which performs _speculative symbolic
execution_.
That is, it not only executes the "correct" or "sequential" paths of a
program, but also the "mispredicted" or "speculative" paths, subject to some
speculation window size.
Pitchfork finds paths where secret data is used in either address
calculations or branch conditions (and thus leaked), even speculatively -
these paths represent Spectre vulnerabilities.
Pitchfork covers Spectre v1, Spectre v1.1, and theoretically Spectre v4 (the
code for v4 is here, but hasn't been tested).

# Installing

- Clone this repo:
    ```bash
    git clone https://github.com/cdisselkoen/pitchfork
    ```
- Install the [pypy](https://pypy.org) JITting Python interpreter (highly recommended),
    rather than using the standard Python interpreter.
    You'll have to set that up first, before continuing with installation.
    E.g., on Mac:
    ```bash
    brew install pypy3
    cd /path/to/where/you/cloned/pitchfork
    pypy3 -m venv [whatever_you_want_to_name_your_virtualenv]
    source [your_virtualenv_name]/bin/activate
    ```
    then proceed with the following steps using the pypy virtualenv. Inside this
    virtualenv, `python` should give you a pypy interpreter rather than an
    ordinary Python one.
    - Pitchfork has only been tested with PyPy 7.0-7.1 (both of which
    implement Python 3.6.1), but it should also work with other PyPy versions
    and even other Python interpreters.
- Install [angr](https://github.com/angr/angr) using the directions [here](https://docs.angr.io/introductory-errata/install)
    - Pitchfork currently only works with angr version 8.19.4.5 (latest in Pip as of this writing)
    - You won't actually be using this angr, as Pitchfork requires a slightly
    patched version of angr which we'll install next. But performing the typical
    angr install process ensures that all dependencies (Python and otherwise) for
    angr 8.19.4.5 are properly installed
- Clone [our fork of angr](https://github.com/cdisselkoen/angr) _inside_ this `pitchfork` directory, then checkout its `more-hooks` branch:
    ```bash
    cd pitchfork
    git clone https://github.com/cdisselkoen/angr
    cd angr
    git checkout more-hooks
    cd ..
    ```
    - We recommend cloning our angr fork inside this `pitchfork` directory so
    that Python automatically uses it instead of the pip-installed angr. If you
    clone our angr fork somewhere else, you'll have to put that location on your
    `PYTHONPATH` and do `pip uninstall angr` (which will uninstall angr itself
    but leave all of its other dependencies in place).

# Running

- Make sure you activate your Python virtualenv:
    ```bash
    cd pitchfork
    source [your_virtualenv_name]/bin/activate
    ```
- Run `python pitchfork.py` to run tests against all the original Kocher test
cases, our new Spectre v1 test cases, and our Spectre v1.1 test cases (see
below).
- Explanations of expected Kocher test results are in [kocher_analysis.txt](kocher_analysis.txt) (see also the new Spectre testcases)
- To run other tests or workloads, look at the functions in [pitchfork.py](pitchfork.py)
- Some useful utilities for interactive investigation are in [interactiveutils.py](interactiveutils.py) (imported with [pitchfork.py](pitchfork.py))

# Our Spectre testcases

We have three sets of Spectre testcases:

- The original well-known Kocher testcases for Spectre v1.
We are using the versions from Spectector; both the sources and binaries
can be found in the [spectector-clang](spectector-clang) folder.

- A revised version of the Kocher testcases.
The main difference in our revision is when executed _non-speculatively_,
our revised testcases do not perform out-of-bounds or secret-dependent memory
accesses, or branch on secret data.
These cases are found in [new-testcases/spectrev1.c](new-testcases/spectrev1.c);
detailed explanations of changes can be found in comments in that file.

- A new set of testcases for Spectre v1.1.
Spectre v1.1 is similar to Spectre v1 except that it relies on out-of-bounds
writes rather than out-of-bounds reads.
Our testcases demonstrate a variety of ways that these vulnerabilities can appear.
They are found in [new-testcases/forwarding.c](new-testcases/forwarding.c);
detailed explanations of each of the cases can be found in comments in that file.
