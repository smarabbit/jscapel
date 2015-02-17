{
	.name		= "tracebyname",
	.args_type	= "procname:s?",
	.mhandler.cmd	= do_browserstub,
	.params		= "[procname]",
	.help		= "Run the tests with program [procname]"
},

{
	.name		= "dumpstring",
	.args_type	= "filename:s?",
	.mhandler.cmd	= do_dumpstring,
	.params		= "[filename]",
	.help		= "Dump heap data into file"
},
{
	.name		= "dumpcodetrace",
	.args_type	= "filename:s?",
	.mhandler.cmd	= do_dumpcodetrace,
	.params		= "[filename]",
	.help		= "Dump code trace into file"
},
{
	.name		= "dumpcode",
	.args_type	= "filename:s?",
	.mhandler.cmd	= do_dumpcode,
	.params		= "[filename]",
	.help		= "Dump code  into file"
},
{
	.name		= "dumpall",
	.args_type	= "filename:s?",
	.mhandler.cmd	= do_dumpall,
	.params		= "[filename]",
	.help		= "Dump code and code trace  into file"
},
{
	.name		= "startmonitor",
	.args_type	= "",
	.mhandler.cmd	= do_startmonitor,
	.params		= "",
	.help		= "start to register hooks to monitor heap allocations and js operations"
},
{
	.name		= "trace_stop",
	.args_type	= "",
	.mhandler.cmd	= do_tracestop,
	.params		= "",
	.help		= "start to register hooks to monitor heap allocations and js operations"
},
{
        .name           = "monitor_proc",
        .args_type      = "procname:s?",
        .mhandler.cmd   = do_monitor_proc,
        .params         = "[procname]",
        .help           = "Run the tests with program [procname]"
},
{
        .name = "set_guest_drive",
        .args_type = "guest_dir:s?",
        .mhandler.cmd = do_set_guest_dir,
        .params = "[guest_dir]",
        .help = "Set the location on host where guest fs is mapped"
},

{
        .name = "set_print_stack",
        .args_type = "",
        .mhandler.cmd = do_set_print_stack,
        .params = "",
        .help = "enabling printing of stack activities "
},
