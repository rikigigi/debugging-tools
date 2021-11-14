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

 The non portable code is located in [frida.js](frida.js). Yes it is javascript.
 
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

Later this is used by an `Interceptor.attach` call, that tells FRIDA to execute some code when the cp.x code enters/exits a function. The symbols can be found with `nm cp.x | grep your_function_name`
```
Interceptor.attach(
      DebugSymbol.fromName('nlfl_bgrp_x_').address,
      {
          onEnter : function(args) {
                       this._fionv=args[4];
                       send('enter '+JSON.stringify(read_gfc_array_descriptor_9_3(this._fionv)));
                       send("enter_nlfl_bgrp_x_", read_gfc_array_9_3(this._fionv));
                       send("enter_nlfl_bgrp_x_lambda", read_gfc_array_9_3(args[2]));
                    },
          onLeave: function() {
             send("exit_nlfl_bgrp_x_",read_gfc_array_9_3(this._fionv));}
      });

```
In this snippet the target function in fortran was named `nlfl_bgrp_x` and the target array was an assumed shape array located in position 5. If the array is not assumed shape it is simply a pointer and the size cannot be found in any descriptor, because there is no one. Then the data is sent to the python part of the code with the `send` call. The python part then transforms the array in a numpy array, and then it is elaborated.

# example output

(this is exactly the second command after running the first one)

(...)
```
=====enter runcg nfi 1=====
=====enter [["0x7ffe2f208010","0x7ffe2f208018",[8,0,2,3,0],8,[[[1,1,3]],[[3,1,18]]]],{"base_addr":"0x7ffe2f208010","offset":"0x7ffe2f208018","dtype":{"elem_len":8,"version":0,"rank":2,"type":3,"attribute":0},"span":8,"dim":[{"stride,lowb,upb":[1,1,3]},{"stride,lowb,upb":[3,1,18]}]}]=====
=====enter vofrho nfi 1=====
size of data: 8
reading from exit_vofrho_1_0.npy
1.7208456881689926e-14
=====exit_vofrho_1=====
=====enter [["0x7ffe2f207080","0x7ffe2f207088",[8,0,2,3,0],8,[[[1,1,3]],[[3,1,18]]]],{"base_addr":"0x7ffe2f207080","offset":"0x7ffe2f207088","dtype":{"elem_len":8,"version":0,"rank":2,"type":3,"attribute":0},"span":8,"dim":[{"stride,lowb,upb":[1,1,3]},{"stride,lowb,upb":[3,1,18]}]}]=====
=====enter vofrho nfi 1=====
  -10.635051845812505       -695.50773003151687       -127.94022768457629       0.34262536041149200        348.47133242459370        348.47133242459370     
size of data: 8
reading from exit_vofrho_1_1.npy
4.935982178544407e-14
=====exit_vofrho_1=====
=====enter [["0x7ffe2f207080","0x7ffe2f207088",[8,0,2,3,0],8,[[[1,1,3]],[[3,1,18]]]],{"base_addr":"0x7ffe2f207080","offset":"0x7ffe2f207088","dtype":{"elem_len":8,"version":0,"rank":2,"type":3,"attribute":0},"span":8,"dim":[{"stride,lowb,upb":[1,1,3]},{"stride,lowb,upb":[3,1,18]}]}]=====
=====enter vofrho nfi 1=====
size of data: 8
reading from exit_vofrho_1_2.npy
4.493107275127528e-14
=====exit_vofrho_1=====
=====enter [["0x7ffe2f207080","0x7ffe2f207088",[8,0,2,3,0],8,[[[1,1,3]],[[3,1,18]]]],{"base_addr":"0x7ffe2f207080","offset":"0x7ffe2f207088","dtype":{"elem_len":8,"version":0,"rank":2,"type":3,"attribute":0},"span":8,"dim":[{"stride,lowb,upb":[1,1,3]},{"stride,lowb,upb":[3,1,18]}]}]=====
=====enter vofrho nfi 1=====
  -130.84447520043895       -288.84280961963776       -152.20710957382073       0.38407917555222459       0.38141282120997438        132.91143401086310     
size of data: 8
reading from exit_vofrho_1_3.npy
9.698665481838731e-14
=====exit_vofrho_1=====
=====enter [["0x7ffe2f207080","0x7ffe2f207088",[8,0,2,3,0],8,[[[1,1,3]],[[3,1,18]]]],{"base_addr":"0x7ffe2f207080","offset":"0x7ffe2f207088","dtype":{"elem_len":8,"version":0,"rank":2,"type":3,"attribute":0},"span":8,"dim":[{"stride,lowb,upb":[1,1,3]},{"stride,lowb,upb":[3,1,18]}]}]=====
=====enter vofrho nfi 1=====
size of data: 8
reading from exit_vofrho_1_4.npy
8.333611578592581e-14
=====exit_vofrho_1=====
=====enter [["0x7ffe2f207080","0x7ffe2f207088",[8,0,2,3,0],8,[[[1,1,3]],[[3,1,18]]]],{"base_addr":"0x7ffe2f207080","offset":"0x7ffe2f207088","dtype":{"elem_len":8,"version":0,"rank":2,"type":3,"attribute":0},"span":8,"dim":[{"stride,lowb,upb":[1,1,3]},{"stride,lowb,upb":[3,1,18]}]}]=====
=====enter vofrho nfi 1=====
  -168.86945483002319       -128.32986354948616       -163.06581970914110       0.36272424345329923       0.57020687304057704        75.787013178673249     
size of data: 8
reading from exit_vofrho_1_5.npy
1.848798891757042e-13
=====exit_vofrho_1=====
```
(...)


