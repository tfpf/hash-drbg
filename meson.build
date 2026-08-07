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
hdrbg = shared_library(
    'hdrbg',
    source_files,
    install: true,
)
install_headers(
  source_directory / 'hdrbg.h',
  subdir: 'hdrbg',
)

pkg = import('pkgconfig')
pkg.generate(
  hdrbg,
)

source_files += source_directory / 'pyhdrbg.c'
py = import('python').find_installation(pure: false)
py.extension_module(
    'hdrbg',
    source_files,
    install: true,
)
