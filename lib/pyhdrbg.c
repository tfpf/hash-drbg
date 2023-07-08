#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <inttypes.h>
#include <stdbool.h>

#include "hdrbg.h"


static PyObject *
Rand(PyObject *self, PyObject *args)
{
    uint64_t r = hdrbg_rand(NULL);
    if(hdrbg_err_get() == HDRBG_ERR_OUT_OF_MEMORY)
    {
        return PyErr_NoMemory();
    }
    return PyLong_FromUnsignedLongLong(r);
}


static PyObject *
Real(PyObject *self, PyObject *args)
{
    double long r = hdrbg_real(NULL);
    if(hdrbg_err_get() == HDRBG_ERR_OUT_OF_MEMORY)
    {
        return PyErr_NoMemory();
    }
    return PyFloat_FromDouble(r);
}


// Module information.
PyDoc_STRVAR(
    rand_doc,
    "rand() -> int\n"
    "Generate a cryptographically secure pseudorandom number using the HDRBG object. If it had not been previously "
    "initialised, the behaviour is undefined.\n\n"
    ":return: Uniform pseudorandom integer in the range 0 (inclusive) to 2 ** 64 − 1 (inclusive)."
);
PyDoc_STRVAR(
    real_doc,
    "real() -> float\n"
    "Generate a cryptographically secure pseudorandom fraction using the HDRBG object. If it had not been previously "
    "initialised/reinitialised, the behaviour is undefined.\n\n"
    ":return: Uniform pseudorandom real in the range 0 (inclusive) to 1 (inclusive)."
);
static PyMethodDef pyhdrbg_methods[] =
{
    {"rand", Rand, METH_NOARGS, rand_doc},
    {"real", Real, METH_NOARGS, real_doc},
    {NULL, NULL, 0, NULL},
};
static PyModuleDef pyhdrbg_module =
{
    PyModuleDef_HEAD_INIT,
    "hdrbg",
    "Python API for a C implementation of Hash DRBG "
    "(see https://github.com/tfpf/hash-drbg/blob/main/doc for the full documentation)",
    -1,
    pyhdrbg_methods,
};


PyMODINIT_FUNC
PyInit_hdrbg(void)
{
    hdrbg_init(false);
    switch(hdrbg_err_get())
    {
        case HDRBG_ERR_OUT_OF_MEMORY: return PyErr_NoMemory();
        case HDRBG_ERR_NO_ENTROPY: return PyErr_Format(PyExc_OSError, "Entropy source not found.");
        case HDRBG_ERR_INSUFFICIENT_ENTROPY: return PyErr_Format(PyExc_RuntimeError, "Insufficient entropy.");
        default:
    }
    return PyModule_Create(&pyhdrbg_module);
}
