from setuptools import Extension, find_packages, setup

ext_modules = [Extension(
    name='hdrbg',
    sources=['lib/pyhdrbg.c', 'lib/hdrbg.c', 'lib/sha256.c', 'lib/extras.c'],
    include_dirs=['include'],
    py_limited_api=True,
)]
kwargs = dict(
    package_dir={'': 'lib'},
    ext_modules=ext_modules,
)
setup(**kwargs)
