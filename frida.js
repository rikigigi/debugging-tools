const fion_idx=15;
const fion_idx_v=16;
const nat=18;
const pSize = Process.pointerSize;


function read_struct(ptr,desc, nrep){
  var offset=0;
  var result_ = [];
  var rdict_ = {};
  desc.forEach(function (item, index, arr){
     const n = item[0]
     const type = item[1];
     const name = item[2];
     var rep = n;
     if (n < 0) {
        rep = nrep;
     }
     var result = [];
     if (typeof type === 'string' || type instanceof String) {
       for (var i =0;i<rep;++i) {
          switch(type) {
              case "ptr":
                 result.push(ptr.add(offset));
                 offset += pSize;
                 break;
              case "int32":
                 result.push(ptr.add(offset).readS32());
                 offset += 4;
                 break;
              case "uint32":
                 result.push(ptr.add(offset).readU32());
                 offset += 4;
                 break;
              case "int64":
                 result.push(ptr.add(offset).readS64().toNumber());
                 offset += 8;
                 break;
              case "uint64":
                 result.push(ptr.add(offset).readU64().toNumber());
                 offset += 8;
                 break;
              case "int16":
                 result.push(ptr.add(offset).readS16());
                 offset += 2;
                 break;
              case "int8":
                 result.push(ptr.add(offset).readS8());
                 offset += 1;
                 break;
              case "int8_nrep":
                 const n =ptr.add(offset).readS8();
                 result.push(n);
                 nrep = n;
                 offset += 1;
                 break;
          }
       }
       if (rep>1) {
         rdict_[name] = result ;
       } else if (rep==1) {
         rdict_[name] = result[0];
       }
     } else {
       var rdict_l = [];
       for (var i =0;i<rep;++i) {
          const r_ = read_struct(ptr.add(offset),type, nrep)
          result.push(r_[2]);
          nrep=r_[0];
          offset += r_[1];
          rdict_l.push(r_[3]);
       }
       if (rep>1) {
         rdict_[name] = rdict_l ;
       } else if (rep==1) {
         rdict_[name] = rdict_l[0];
       }
     }
     if (rep>1) {
        result_.push(result);
     } else if (rep==1) {
        result_.push(result[0]);    
     }
  });
  //console.log(JSON.stringify(result_));
  //console.log(JSON.stringify(rdict_));
  return [nrep, offset, result_, rdict_];  
}

function read_gfc_array_descriptor_9_3(ptr){
   const indexType = "int64"
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
   const r_ = read_struct(ptr, desc, 0);
   return [r_[2], r_[3]];
}

function read_gfc_array_9_3(ptr) {
   const descr = read_gfc_array_descriptor_9_3(ptr)[1];
   const rank = descr['dtype']['rank'];
   var tot_size=1;
   for (var i =0; i< rank; ++i) {
      const dim = descr['dim'][i]['stride,lowb,upb'];
      tot_size = tot_size*(dim[2]-dim[1]+1);
   }
   console.log('size of data: ' + descr['dtype']['elem_len']);
   return descr['base_addr'].readPointer().readByteArray(tot_size*descr['dtype']['elem_len']);
}


function get_runcg_addr(){
  if (DebugSymbol.fromName('__cg_sub_MOD_runcg_uspp').address == 0x0){
   return DebugSymbol.fromName('runcg_uspp_').address
  } else {
   return DebugSymbol.fromName('__cg_sub_MOD_runcg_uspp').address
  }
}

Interceptor.attach(
      get_runcg_addr(),
      {
          onEnter : function(args) {
                       this._arg0=args[0].readPointer().toInt32();
                       this._fion=args[fion_idx];
                       send("enter runcg nfi " + this._arg0 );
                    },
          onLeave: function() {send("exit_runcg_nfi_"+this._arg0,this._fion.readByteArray(nat*3*8));}
      });
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
        //const bt = '' + Thread.backtrace(this.context, Backtracer.ACCURATE)
        //.map(DebugSymbol.fromAddress).join('\n') + '\n';
             send("exit_nlfl_bgrp_x_",read_gfc_array_9_3(this._fionv));}
      });
Interceptor.attach(
      DebugSymbol.fromName('nlfq_bgrp_x_').address,
      {
          onEnter : function(args) {
                       this._fionv=args[4];
                       send('enter '+JSON.stringify(read_gfc_array_descriptor_9_3(this._fionv)));
                       send("enter_nlfq_bgrp_x_", read_gfc_array_9_3(this._fionv));
                    },
          onLeave: function() {
        //const bt = '' + Thread.backtrace(this.context, Backtracer.ACCURATE)
        //.map(DebugSymbol.fromAddress).join('\n') + '\n';
             send("exit_nlfq_bgrp_x_",read_gfc_array_9_3(this._fionv));}
      });
Interceptor.attach(
      DebugSymbol.fromName('vofrho_x_').address,
      {
          onEnter : function(args) {
                       this._arg0v=args[0].readPointer().toInt32();
                       this._fionv=args[fion_idx_v];
                       send('enter '+JSON.stringify(read_gfc_array_descriptor_9_3(this._fionv)));
                       send("enter vofrho nfi " + this._arg0v );
                    },
          onLeave: function() {
        const bt = '' + Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n';
             send("exit_vofrho_"+this._arg0v,read_gfc_array_9_3(this._fionv));}
      });
//Interceptor.attach(
//      DebugSymbol.fromName('vofesr_').address,
//      {
//          onEnter : function(args) {
//                       this._arg0v=args[0].readPointer().toInt32();
//                       this._fionv=args[3];
//                       for (var i=0; i<7; ++i) {
//                         console.log(JSON.stringify(read_gfc_array_descriptor_9_3(args[i])[0]));
//                       }
//                       var fionv = read_gfc_array_9_3(this._fionv);
//                       send("enter vofesr nfi " + this._arg0v,fionv );
//                    },
//          onLeave: function() {send("exit vofesr nfi "+this._arg0v,read_gfc_array_9_3(this._fionv));}
//      });

