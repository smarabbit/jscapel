

Components.utils.import("resource://gre/modules/ctypes.jsm");
var lib;
var EXPORTED_SYMBOLS = ["bs"];
var fbs =
{
		initialize: function()
		{
			lib= ctypes.open("c:\\stub.dll");
		},
		close:function()
		{
			lib.close();
		},
		compiled_script: fucntion(compiled_script)
		{
				var compiled_script_stub = lib.declare("compiled_script",
									 ctypes.winapi_abi,
									 ctypes.int32_t,
									 ctypes.jschar.ptr,
									 ctypes.int32_t
									 );
				var ret = compiled_script_stub(0, compiled_script.length, compiled_script);
		},
		browserstub: function()
		{
			var libs = ctypes.open("C:\\WINDOWS\\system32\\user32.dll");

			var msgBox = libs.declare("MessageBoxW",
					ctypes.winapi_abi,
					ctypes.int32_t,
					ctypes.int32_t,
					ctypes.jschar.ptr,
					ctypes.jschar.ptr,
					ctypes.int32_t
			 	);
			var MB_OK = 3;

			var ret = msgBox(0,"hellor world browser stub", "title", MB_OK);
			alert("MessageBox result:"+ ret);

			libs.close();
	
		},
		testdll: function()
		{
			var addF = lib.declare("add",ctypes.winapi_abi,ctypes.int32_t,ctypes.int32_t,ctypes.int32_t);
	
			var ret = addF(5,6);
			alert("5+6=  "+ret);
		}
};

