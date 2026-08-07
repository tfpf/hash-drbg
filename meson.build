project(
    'hdrbg',
    'c',
)

source_directory = 'lib'
source_files = files(
    source_directory / 'extras.c',
    source_directory / 'hdrbg.c',
    source_directory / 'sha256.c',
)
shared_library(
    'hdrbg',
    source_files,
    install: true,
)

source_files += source_directory / 'pyhdrbg.c'
py = import('python').find_installation(pure: false)
py.extension_module(
    'hdrbg',
    source_files,
    install: true,
)
