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
    - This code has only been tested with PyPy 7.1.0-beta0 (which implements Python 3.6.1).
- Inside your Python virtualenv, run `python driver.py` to run tests against all the Kocher
test cases and our forwarding test cases
- Current status / explanations of expected Kocher test results is in [kocher_analysis.txt](kocher_analysis.txt)
- For things other than Kocher and forwarding test cases, look at the functions in driver.py
- Some useful utilities for interactive investigation are in [utils.py](utils.py) (imported with [driver.py](driver.py))
