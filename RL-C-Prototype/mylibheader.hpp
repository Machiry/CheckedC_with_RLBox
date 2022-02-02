#include <stdint.h>
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
   /* This is the interface for Checked-C library to access the unchecked library code 
    */
#define invoked_unchecked_function(func_name, a, b, result)\
{\
	execute_unchecked_function(_unsafe_add,a,b,result);\
}\

    //THIS .H FILE INTERFACES THE API'S OF ALL LIBRARIES UNDER USE
    //THIS WILL NOT USE CHECKEDC AND THEREBY, UNCONVERTED C 
    //LIBRARY DECLARATIONS ARE CULMINATED HERE
    
    /* Data-type larger than DTYPE, for holding intermediate results of calculations */
    #define DTYPE_TMP                uint32_t
    #define sandbox_fields_reflection_mylibheader_class_bn(f, ...) \
	f(uint32[10000], array, FIELD_NORMAL, ##__VA_ARGS__)g()\
    
    #define sandbox_fields_reflection_mylibheader_allClasses(f, ...) \
	f(bn, mylibheader, ##__VA_ARGS__)
    //belong to library1
    void hello();
    /* Data-holding structure: array of DTYPEs */
    struct bn
    {
       uint32_t array[10000];
    };

    unsigned add(unsigned, unsigned);
    void echo(const char* str);
    
    //belong to lib2
    /* Initialization functions: */
    void bignum_init(struct bn* n);
    void bignum_from_int(struct bn* n, DTYPE_TMP i);
    int  bignum_to_int(struct bn* n);
    void bignum_from_string(struct bn* n, char* str, int nbytes);
    void bignum_to_string(struct bn* n, char* str, int maxsize);

    /* Basic arithmetic operations: */
    void bignum_add(struct bn* a, struct bn* b, struct bn* c); /* c = a + b */

    /* Bitwise operations: */
    void bignum_rshift(struct bn* a, struct bn* b, int nbits); /* b = a >> nbits */

    /* Special operators and comparison */
    void bignum_isqrt(struct bn* a, struct bn* b);             /* Integer square root -- e.g. isqrt(5) => 2*/
    int call_cb(int (*cb) (const char* str));
    void _unsafe_add(int* a, int* b, int* sum);
#ifdef __cplusplus
}

bool execute_unchecked_function(char* func_name, int* a, int*b, int* result);
#endif
