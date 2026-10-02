# Cryptomnio Gem Gemspec

require_relative "lib/cryptomnio/version"

Gem::Specification.new do |s|
	s.name    = "cryptomnio"
	s.version = Cryptomnio::VERSION
	s.date    = Cryptomnio::DATE
	s.summary = "Cryptomnio API Interface"
	s.description = "A Ruby gem providing an interface to the Cryptomnio API"
	s.authors     = ["Dustin D. Trammell"]
	s.email       = "info@cryptomnio.com"
	s.files       = ["lib/cryptomnio.rb", "lib/cryptomnio/version.rb", "LICENSE"]
	s.homepage    = "https://github.com/dtrammell/ruby-cryptomnio"
	s.license     = "MIT"
	s.required_ruby_version = ">= 3.3"
	s.add_runtime_dependency "rest-client", "~> 2.1"
#	s.add_runtime_dependency "daemons",
#		[">= 0.0.1"]
#	s.add_development_dependency "bourne",
#		[">= 0.0.1"]

end
