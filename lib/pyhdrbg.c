#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <inttypes.h>
#include <stdbool.h>

#include "hdrbg.h"


#define HDRBG_HANDLE_ERROR  \
do  \
{  \
    switch(hdrbg_err_get())  \
    {  \
        case HDRBG_ERR_OUT_OF_MEMORY: return PyErr_NoMemory();  \
        case HDRBG_ERR_NO_ENTROPY: return PyErr_Format(PyExc_OSError, "Entropy source not found.");  \
        case HDRBG_ERR_INSUFFICIENT_ENTROPY: return PyErr_Format(PyExc_RuntimeError, "Insufficient entropy.");  \
        case HDRBG_ERR_INVALID_REQUEST: return PyErr_Format(PyExc_ValueError, "Can generate only 1 to 65536 bytes at once.");  \
        default:  \
    }  \
}  \
while(false)


static PyObject *
Bytes(PyObject *self, PyObject *args)
{
    Py_ssize_t r_length;
    if(!PyArg_ParseTuple(args, "n", &r_length))
    {
        return NULL;
    }
    static uint8_t r_bytes[65536ULL];
    hdrbg_fill(NULL, false, r_bytes, r_length);
    HDRBG_HANDLE_ERROR;

    // This is okay: CPython works only on systems on which `char` is 8 bits
    // wide.
    return PyBytes_FromStringAndSize((char *)r_bytes, r_length);
}


static PyObject *
Rand(PyObject *self, PyObject *args)
{
    uint64_t r = hdrbg_rand(NULL);
    HDRBG_HANDLE_ERROR;
    return PyLong_FromUnsignedLongLong(r);
}


static PyObject *
Real(PyObject *self, PyObject *args)
{
    double long r = hdrbg_real(NULL);
    HDRBG_HANDLE_ERROR;
    return PyFloat_FromDouble(r);
}


// Module information.
PyDoc_STRVAR(
    bytes_doc,
    "bytes(r_length) -> bytes\n"
    "Generate cryptographically secure pseudorandom bytes.\n\n"
    ":param r_length: Number of bytes to generate. At most 65536.\n\n"
    ":return: Uniform pseudorandom bytes object."
);
PyDoc_STRVAR(
    rand_doc,
    "rand() -> int\n"
    "Generate a cryptographically secure pseudorandom number.\n\n"
    ":return: Uniform pseudorandom integer in the range 0 (inclusive) to 2 ** 64 − 1 (inclusive)."
);
PyDoc_STRVAR(
    real_doc,
    "real() -> float\n"
    "Generate a cryptographically secure pseudorandom fraction.\n\n"
    ":return: Uniform pseudorandom real in the range 0 (inclusive) to 1 (inclusive)."
);
static PyMethodDef pyhdrbg_methods[] =
{
    {"bytes", Bytes, METH_VARARGS, bytes_doc},
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
    if(hdrbg_init(false) == NULL)
    {
        HDRBG_HANDLE_ERROR;
    }
    return PyModule_Create(&pyhdrbg_module);
}
