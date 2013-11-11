Gem::Specification.new do |spec|
  spec.name              = 'zip_ruby'
  spec.version           = '0.3.8'
  spec.summary           = 'Ruby bindings for libzip, namespaced'
  spec.files             = Dir.glob('ext/*.*') + %w(ext/extconf.rb README.txt zip_ruby.c LICENSE.libzip ChangeLog)
  spec.author            = 'winebarrel, Matthias Grosser'
  spec.email             = 'mtgrosser@gmx.net'
  spec.homepage          = 'https://github.com/onrooby/zip_ruby'
  spec.extensions        = 'ext/extconf.rb'
  spec.has_rdoc          = true
  spec.rdoc_options      << '--title' << 'ZipRuby - Ruby bindings for libzip.'
  spec.extra_rdoc_files  = %w(README.txt zip_ruby.c LICENSE.libzip ChangeLog)
end
