lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require_relative 'lib/omniauth/reinz/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-reinz"
  spec.version       = Omniauth::REINZ::VERSION
  spec.authors       = ["Realhub Systems"]
  spec.email         = ["support@realhub.com.au"]

  spec.summary       = %q{A REINZ OAuth2 strategy for OmniAuth}
  spec.description   = %q{A REINZ OAuth2 strategy for OmniAuth. This allows you to login to REINZ with your ruby app.}
  spec.homepage      = "https://github.com/realhub/omniauth-reinz"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/realhub/omniauth-reinz.git"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "byebug", "~> 11"
end
