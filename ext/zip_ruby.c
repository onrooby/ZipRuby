#ifdef _WIN32
__declspec(dllexport) void Init_zip_ruby(void);
#endif

#include "zip_ruby.h"
#include "zip_ruby_zip.h"
#include "zip_ruby_archive.h"
#include "zip_ruby_file.h"
#include "zip_ruby_stat.h"
#include "zip_ruby_error.h"

void Init_zip_ruby() {
  Init_zipruby_zip();
  Init_zipruby_archive();
  Init_zipruby_file();
  Init_zipruby_stat();
  Init_zipruby_error();
}
