#include "zip_ruby.h"
#include "zip_ruby_error.h"
#include "ruby.h"

extern VALUE Zip;
VALUE Error;

void Init_zipruby_error() {
  Error = rb_define_class_under(Zip, "Error", rb_eStandardError);
}
