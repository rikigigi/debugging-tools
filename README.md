# Debugging a Fortran Code with FRIDA

This code was used to compare different versione of [Quantum Espresso](https://gitlab.com/QEF/q-e)'s `cp.x`.
It has the advantage that if you need to compare different version you don't have to insert custom code in every version or use complicated debugging programs like this one but possibly not reproducible.

You need `pip install frida` and
it is run as the following:

	python debug-fortran-frida.py true ~/q-e/build/bin/cp.x -in sio2-us-lda-cg.in

or
	python debug-fortran-frida.py false ~/q-e_develCG/build/bin/cp.x -in sio2-us-lda-cg.in

It does the following:

  - intercept the calls to specified functions
  - read the assumed shaped fortran array format of gfortran, version 9.3
  - write on disk as numpy array (as in the first command above) or, alternatively
  - read from disk and compare with the computed array (as in the second command above). If they are different above a threshold, also the computed array is saved with a different name to allow comparison using, for example, a jupyter notebook and matplotlib to plot the difference in an image
  - drive you into the madness

# porting to different compilers

 The non portable code is located in [](frida.js). Yes it is javascript.
 
 The headache comes from the fortran array descriptor, that is not fixed by the standard. So I built some facilities to read this in a fast way without much work if you change compiler.
 In the code the most core function is `read_struct` that is a convenient way of reading memory into a javascript dictionary given an array that describes how the memory is used. The array descriptor format for gfortran 9.3 is read by the function `read_gfc_array_descriptor_9_3`. The array passed to `read_struct` function has the following format:

	[ [ #number of reps , data type, name in the output dictionary ] ,
	  [ ...  , ... , ... ],
	  [ #number of reps, [ the data type can be an other list with the same format as this one ], name in the output dictionary ]
	]

where `data type` is one of the following strings:
  - `ptr`
  - `int32`
  - `uint32`
  - `int64`
  - `uint64`
  - `int16`
  - `uint16`
  - `int8`
  - `int8_nrep`

`int8_nrep` has a spectial meaning: the number that it reads is taken as the number of repetition if `#number of reps` is negative.
So for gfortran this array becomes:

	   const desc = [
	              [1,"ptr","base_addr"],
	              [1,"ptr","offset"],
	              [1,  [
	                      [1,"uint64","elem_len"],
	                      [1,"int32","version"],
	                      [1,"int8_nrep","rank"],
	                      [1,"int8","type"],
	                      [1,"int16","attribute"]
	                   ], "dtype"
	              ],
	              [1,indexType,"span"],
	              [-1, [
	                      [3,indexType,"stride,lowb,upb"]  // [stride,lower_bound,upper_bound]
	                   ], "dim"
	              ]
	          ];

The source of this information for gfortran is the source code: the struct of the description is found in the `libgfortran\libgfortran.h` of the gcc source distribution:


	 typedef struct descriptor_dimension
	 {
	   index_type _stride;
	   index_type lower_bound;
	   index_type _ubound;
	 }
	 descriptor_dimension;
	 
	 typedef struct dtype_type
	 {
	   size_t elem_len;
	   int version;
	   signed char rank;
	   signed char type;
	   signed short attribute;
	 }
	 dtype_type;
	 
	 #define GFC_ARRAY_DESCRIPTOR(type) \
	 struct {\
	   type *base_addr;\
	   size_t offset;\
	   dtype_type dtype;\
	   index_type span;\
	   descriptor_dimension dim[];\
	 }

and can ber easily found by grepping `GFC_ARRAY_DESCRIPTOR`. The last struct (defined by a macro) is completely equivalent by the array provided above when speaking of memory layout

