
from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy as np

extensions = [
    Extension(
        "btc_cracker.core",
        ["btc_cracker/core.pyx"],
        extra_compile_args=["-O3", "-march=native", "-fopenmp"],
        extra_link_args=["-fopenmp"],
        include_dirs=[np.get_include()]
    )
]

setup(
    name="btc_cracker",
    version="0.1",
    packages=["btc_cracker"],
    ext_modules=cythonize(extensions, compiler_directives={'language_level': "3"}),
    install_requires=[
        'coincurve',
        'psutil',
        'colorama',
        'numpy',
        'numba'
    ]
)
