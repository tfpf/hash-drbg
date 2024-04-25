from setuptools import Extension, setup

ext_modules = [
    Extension(
        name="hdrbg",
        sources=["lib/pyhdrbg.c", "lib/hdrbg.c", "lib/sha256.c", "lib/extras.c"],
        include_dirs=["include"],
        py_limited_api=True,
    )
]
kwargs = {
    "package_dir": {"": "lib"},
    "ext_modules": ext_modules,
}
setup(**kwargs)
