#pragma once

/* Error log */
#define Error(message)\
  std::cout << "\n" << message << std::endl;\
  exit(1);
