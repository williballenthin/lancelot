from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(name='pylancelot',
      version="0.0.1",
      rust_extensions=[RustExtension('pylancelot', 'Cargo.toml',  binding=Binding.PyO3)],
      setup_requires=['pytest-runner'],
      tests_require=['pytest', 'ujson'],
      requires=['ujson'],
      zip_safe=False)
