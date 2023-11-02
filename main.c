#include <stdlib.h>
#ifdef GTK_GUI
#include "gui_mode.h"
#endif
#ifndef GTK_GUI
#include "term_mode.h"
#endif

int main(int argc, char* argv[]) {
  #ifndef GTK_GUI
  init_term();
  #endif
  
  #ifdef GTK_GUI
  init_gui(argc, argv);
  #endif
  return EXIT_SUCCESS;
}
