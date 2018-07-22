# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'passivetotal/version'

Gem::Specification.new do |spec|
  spec.name          = "passivetotal"
  spec.version       = PassiveTotal::VERSION
  spec.authors       = ["chrislee35"]
  spec.email         = ["rubygems@chrislee.dhs.org"]

  spec.summary       = %q{Wrapper library for PassiveTotal.org's W  eb API}
  spec.description   = %q{PassiveTotal offers an extensive API for users of the platform that maps most major actions available in the web application to a corresponding call. There are two flavors of the API available for use, stable and current. In order to use the stable API, add the version indicator (vX) into the URL as documented below. If you would rather use the current API which includes new changes and experiments, replace the version indicator with "current".}
  spec.homepage      = "https://github.com/chrislee35/passivetotal"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features|snapcraft.yaml)/}) }
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "json", "~> 2.0"
  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "minitest"
end
