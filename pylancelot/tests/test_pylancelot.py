import doctest
import pylancelot


def load_tests(loader, tests, ignore):
    print(doctest.DocTestSuite(pylancelot))
    print(pylancelot.from_bytes.__doc__)
    tests.addTests(doctest.DocTestSuite(pylancelot))
    return tests