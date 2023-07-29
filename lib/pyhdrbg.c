#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <inttypes.h>
#include <limits.h>
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
        case HDRBG_ERR_INVALID_REQUEST_FILL:
            PyErr_Format(PyExc_ValueError, "argument 1 must be less than or equal to 65536");
            return -1;
        case HDRBG_ERR_INVALID_REQUEST_UINT:
            PyErr_Format(PyExc_ValueError, "argument 1 must be non-zero");
            return -1;
        case HDRBG_ERR_INVALID_REQUEST_SPAN:
            PyErr_Format(PyExc_ValueError, "argument 1 must be less than argument 2");
            return -1;
        default:
            return 0;
    }
}


static PyObject *
Info(PyObject *self, PyObject *args)
{
    printf("ULONG_MAX = %+lu\n", ULONG_MAX);
    printf("LLONG_MIN = %+lld\n", LLONG_MIN);
    printf("LLONG_MAX = %+lld\n", LLONG_MAX);
    printf("INT64_MIN = %+"PRId64"\n", INT64_MIN);
    printf("INT64_MAX = %+"PRId64"\n", INT64_MAX);
    Py_RETURN_NONE;
}


static PyObject *
Fill(PyObject *self, PyObject *args)
{
    int long unsigned r_length;
    if(!PyArg_ParseTuple(args, "k", &r_length))
    {
        return NULL;
    }
    r_length = PyLong_AsUnsignedLong(PyTuple_GET_ITEM(args, 0));
    if(PyErr_Occurred() != NULL)
    {
        return PyErr_Format(PyExc_OverflowError, "argument 1 is out of range of `unsigned long`");
    }
    static uint8_t r_bytes[65536UL];
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
    if(PyErr_Occurred() != NULL || modulus > UINT64_MAX)
    {
        return PyErr_Format(PyExc_OverflowError, "argument 1 is out of range of `uint64_t`");
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
    if(err != NULL)
    {
        return PyErr_Format(PyExc_OverflowError, "argument 1 or argument 2 is out of range of `long long`");
    }
    else if(left < INT64_MIN || left > INT64_MAX || right < INT64_MIN || right > INT64_MAX)
    {
        return PyErr_Format(PyExc_OverflowError, "argument 1 or argument 2 is out of range of `int64_t`");
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


static void
Zero(void)
{
    hdrbg_zero(NULL);
}


// Module information.
PyDoc_STRVAR(
    info_doc,
    "info()\n"
    "Display the limits of some C integer types. May help debug ``OverflowError``s."
);
PyDoc_STRVAR(
    bytes_doc,
    "fill(r_length) -> bytes\n"
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
PyDoc_STRVAR(
    pyhdrbg_doc,
    "Python API for a C implementation of Hash DRBG "
    "(see https://github.com/tfpf/hash-drbg/blob/main/doc for the full documentation)"
);
static PyMethodDef pyhdrbg_methods[] =
{
    {"info", Info, METH_NOARGS, info_doc},
    {"fill", Fill, METH_VARARGS, bytes_doc},
    {"rand", Rand, METH_NOARGS, rand_doc},
    {"uint", Uint, METH_VARARGS, uint_doc},
    {"span", Span, METH_VARARGS, span_doc},
    {"real", Real, METH_NOARGS, real_doc},
    {NULL, NULL, 0, NULL},
};
static PyModuleDef pyhdrbg =
{
    PyModuleDef_HEAD_INIT,
    "hdrbg",
    pyhdrbg_doc,
    -1,
    pyhdrbg_methods,
    NULL,
    NULL,
    NULL,
    NULL,
};


PyMODINIT_FUNC
PyInit_hdrbg(void)
{
    if(hdrbg_init(false) == NULL)
    {
        ERR_CHECK;
    }
    if(Py_AtExit(Zero) < 0)
    {
        return NULL;
    }
    return PyModule_Create(&pyhdrbg);
}
