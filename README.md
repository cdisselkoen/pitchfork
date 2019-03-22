# How to Run

- Install [angr](https://github.com/angr/angr) using the directions [here](https://docs.angr.io/introductory-errata/install)
    - NOTE: currently only tested with angr 8.19.2.4
    - It is highly recommended to use the [pypy](https://pypy.org) JITting Python interpreter
        rather than the standard Python interpreter. E.g., on Mac:
        ```bash
        brew install pypy3
        cd /path/to/where/you/want/angr/to/live
        pypy3 -m venv [whatever_you_want_to_name_your_virtualenv]
        source [your_virtualenv_name]/bin/activate
        ```
        then proceed with the standard angr installation using the pypy virtualenv. Inside this virtualenv, `python` should give you a pypy interpreter rather than an ordinary Python one.
- Inside your Python virtualenv, run `python driver.py` to run tests against all the Kocher
test cases
- Current status / explanations of expected test results is in [kocher_analysis.txt](kocher_analysis.txt)
