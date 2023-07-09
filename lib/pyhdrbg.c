#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <inttypes.h>
#include <stdbool.h>

#include "hdrbg.h"

#define ERR_CHECK  \
do  \
{  \
    if(err_check() < 0)  \
    {  \
        return NULL;  \
    }  \
}  \
while(false)


/******************************************************************************
 * Check whether the error indicator is set. If yes, set a Python exception.
 *
 * @return If the error indicator was not set: 0. If it was set: -1.
 *****************************************************************************/
static int
err_check(void)
{
    switch(hdrbg_err_get())
    {
        case HDRBG_ERR_OUT_OF_MEMORY:
            PyErr_Format(PyExc_MemoryError, "insufficient memory");
            return -1;
        case HDRBG_ERR_NO_ENTROPY:
            PyErr_Format(PyExc_OSError, "entropy source not found");
            return -1;
        case HDRBG_ERR_INSUFFICIENT_ENTROPY:
            PyErr_Format(PyExc_RuntimeError, "insufficient entropy");
            return -1;
        case HDRBG_ERR_INVALID_REQUEST:
            PyErr_Format(PyExc_ValueError, "argument 1 must be an integer in [0, 65536]");
            return -1;
        default:
            return 0;
    }
}


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
    ERR_CHECK;

    // This is okay: CPython works only on systems on which `char` is 8 bits
    // wide.
    return PyBytes_FromStringAndSize((char *)r_bytes, r_length);
}


static PyObject *
Rand(PyObject *self, PyObject *args)
{
    uint64_t r = hdrbg_rand(NULL);
    ERR_CHECK;
    return PyLong_FromUnsignedLongLong(r);
}


static PyObject *
Uint(PyObject *self, PyObject *args)
{
    int long long unsigned modulus;
    if(!PyArg_ParseTuple(args, "K", &modulus))
    {
        return NULL;
    }
    modulus = PyLong_AsUnsignedLongLong(PyTuple_GET_ITEM(args, 0));
    if(PyErr_Occurred() != NULL || modulus == 0 || modulus > UINT64_MAX)
    {
        return PyErr_Format(PyExc_ValueError, "argument 1 must be an integer in [1, %"PRIu64"]", UINT64_MAX);
    }
    uint64_t r = hdrbg_uint(NULL, modulus);
    ERR_CHECK;
    return PyLong_FromUnsignedLongLong(r);
}


static PyObject *
Span(PyObject *self, PyObject *args)
{
    int long long left, right;
    PyObject *err = NULL;
    if(!PyArg_ParseTuple(args, "LL", &left, &right))
    {
        err = PyErr_Occurred();
        if(!PyErr_GivenExceptionMatches(err, PyExc_OverflowError))
        {
            return NULL;
        }
    }
    if(err != NULL || left < INT64_MIN || left > INT64_MAX || right < INT64_MIN || right > INT64_MAX || left >= right)
    {
        return PyErr_Format(
            PyExc_ValueError,
            "argument 1 must be less than argument 2; both must be integers in [%"PRId64", %"PRId64"] "
            "and fit in the C `long long` type",
            INT64_MIN, INT64_MAX
        );
    }
    int64_t r = hdrbg_span(NULL, left, right);
    ERR_CHECK;
    return PyLong_FromLongLong(r);
}


static PyObject *
Real(PyObject *self, PyObject *args)
{
    double long r = hdrbg_real(NULL);
    ERR_CHECK;
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
    uint_doc,
    "uint(modulus) -> int\n"
    "Generate a cryptographically secure pseudorandom residue.\n\n"
    ":param modulus: Right end of the interval. Must be positive.\n\n"
    ":return: Uniform pseudorandom integer in the range 0 (inclusive) to ``modulus`` (exclusive)."
);
PyDoc_STRVAR(
    span_doc,
    "span(left, right) -> int\n"
    "Generate a cryptographically secure pseudorandom residue offset.\n\n"
    ":param left: Left end of the interval.\n"
    ":param right: Right end of the interval. Must be greater than ``left``.\n\n"
    ":return: Uniform pseudorandom integer in the range ``left`` (inclusive) to ``right`` (exclusive)."
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
    {"uint", Uint, METH_VARARGS, uint_doc},
    {"span", Span, METH_VARARGS, span_doc},
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
        ERR_CHECK;
    }
    return PyModule_Create(&pyhdrbg_module);
}
