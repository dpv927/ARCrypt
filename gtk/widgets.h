#pragma once_

/* Widget a obtener de archivos */
#define WIDGET_NAME "window"

enum WindowType {
	MAIN_WIN,
	CONFIRM_WIN,
	ERROR_WIN,
	FINISH_WIN,
};

#ifdef TESTING
static const char* win_paths[5] = {
	/* Window type     Window model path  */
	[MAIN_WIN]	   = "models/notebook.glade",
	[CONFIRM_WIN]  = "models/confirm.glade",
	[ERROR_WIN]	   = "models/error.glade",
	[FINISH_WIN]   = "models/finish.glade",
};
#endif

#ifndef TESTING
static const char* win_paths[5] = {
	/* Window type     Window model path  */
	[MAIN_WIN]	   = "gtk/models/notebook.glade",
	[CONFIRM_WIN]  = "gtk/models/confirm.glade",
	[ERROR_WIN]	   = "gtk/models/error.glade",
	[FINISH_WIN]   = "gtk/models/finish.glade",
};
#endif
