

//const Cc = Components.classes;
//const Ci = Components.interfaces;
//const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const debuggerService = Cc["@mozilla.org/js/jsd/debugger-service;1"].getService(Ci.jsdIDebuggerService);
const ioService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
const threadManager = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager);
const prefService = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefBranch);

var appDir, profDir;
var executedScripts = {__proto__: null};
var debuggerWasOn = false;
var debuggerOldFlags;
var filters = {include: [],
			   exclude: ["chrome://","resource://","%APPDIR%","jar:%APPDIR%","%PROFILEDIR%","XStringBundle"]
			  };
var queue = null;

var paused = false;

function start()
{

	fbs.initialize();

	// Initialize debugger
	debuggerWasOn = debuggerService.isOn;
	if (!debuggerWasOn)
	{
		if ("asyncOn" in debuggerService)
		{
			// Gecko 2.0 branch
			debuggerService.asyncOn({onDebuggerActivated: onDebuggerActivated});
		}
		else
		{
			// Gecko 1.9.x branch
			debuggerService.on();
			onDebuggerActivated();
		}
	}
	else
		onDebuggerActivated();
}


function onDebuggerActivated()
{
	debuggerService.scriptHook = scriptHook;
	debuggerService.functionHook = scriptHook;
	debuggerService.topLevelHook = scriptHook;
	debuggerService.interruptHook = stepHook;
	debuggerOldFlags = debuggerService.flags;
	debuggerService.flags = ("DISABLE_OBJECT_TRACE" in Ci.jsdIDebuggerService ? Ci.jsdIDebuggerService.DISABLE_OBJECT_TRACE : 0);
}

function stop()
{
	debuggerService.scriptHook = null;
	debuggerService.functionHook = null;
	debuggerService.topLevelHook = null;
	debuggerService.interruptHook = null;
	debuggerService.flags = debuggerOldFlags;
	if (!debuggerWasOn)
		debuggerService.off();
}
function isFiltered(fileName)
{
	for each (let filter in filters.exclude)
	{
		if (fileName.indexOf(filter) != -1)
			return true;
	}
	return false;
	
	
}
var stepHook =
{
		onExecute: function(frame,type,val)
		{
			
			console.log(" frame ");
			if (type == Ci.jsdIExecutionHook.TYPE_INTERRUPTED)
				{
					console.log("step " + frame.line);
				}
				
		}
		
}	
	
var scriptHook =
{
	onScriptCreated: function(script)
	{
		//console.log(script.functionSource);
		//processAction("compiled", script);
		if(!isFiltered(script.fileName))
		{
			script.enableSingleStepInterrupts(true);
		//	fbs.create_script(script.fileName, script.functionSource);
		}
	},
	onScriptDestroyed: function(script)
	{
	},
	onCall: function(frame, type)
	{
		/*
		if (type == Ci.jsdICallHook.TYPE_TOPLEVEL_START || type == Ci.jsdICallHook.TYPE_FUNCTION_CALL)
			processAction("executed", frame.script);
		else if (type == Ci.jsdICallHook.TYPE_TOPLEVEL_END || type == Ci.jsdICallHook.TYPE_FUNCTION_RETURN)
			processAction("returned", frame.script);
			*/
	},
	
	prevScript: null,
	QueryInterface: XPCOMUtils.generateQI([Ci.jsdIScriptHook, Ci.jsdICallHook])
}


function browserstub(){
	 Components.utils.import("resource://gre/modules/ctypes.jsm");
	 var lib = ctypes.open("C:\\WINDOWS\\system32\\user32.dll");

	 var msgBox = lib.declare("MessageBoxW",
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

	 lib.close();
	
}
function testdll(){
	Components.utils.import("resource://gre/modules/ctypes.jsm");
	var lib = ctypes.open("C:\\stub.dll");
	var addF = lib.declare("add",ctypes.winapi_abi,ctypes.int32_t,ctypes.int32_t,ctypes.int32_t);
	
	var ret = addF(5,6);
	alert("5+6=  "+ret);
}



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
		
		create_script: function(bs_script_file , bs_script_source)
		{
				var create_script_stub = lib.declare("create_script",
									 ctypes.winapi_abi,
									 ctypes.int32_t, //return value
									 ctypes.int32_t,
									 ctypes.int32_t,
									 ctypes.jschar.ptr,
									 ctypes.int32_t,
									 ctypes.jschar.ptr
									 );
				var ret = create_script_stub(0, bs_script_file.length, bs_script_file, bs_script_source.length, bs_script_source);
				console.log(ret);
		}
		
};



///initialize extension
var HelloWorld = {
  onLoad: function() {
    // initialization code
    this.initialized = true;
   
  },

  onMenuItemCommand: function() {
	  start();
	  console.log("hello");	 
	 
    
  }
};

//window.addEventListener("load", function(e) { HelloWorld.onLoad(e); }, false); 
