# -*-ruby-*-
# Copyright: Copyright (c) 2011 RightScale, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# 'Software'), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'rubygems'

Gem::Specification.new do |spec|
  spec.name      = 'right_infrastructure_agent'
  spec.version   = '0.2.1'
  spec.authors   = ['Lee Kirchhoff', 'Raphael Simon']
  spec.email     = 'lee@rightscale.com'
  spec.homepage  = 'https://github.com/rightscale/right_infrastructure_agent'
  spec.platform  = Gem::Platform::RUBY
  spec.summary   = 'RightAgent extension for use by RightScale infrastructure servers'
  spec.has_rdoc  = true
  spec.rdoc_options = ["--main", "README.rdoc", "--title", "RightInfrastructureAgent"]
  spec.extra_rdoc_files = ["README.rdoc"]
  spec.required_ruby_version = '>= 1.8.7'
  spec.require_path = 'lib'

  spec.add_development_dependency('rake', [">= 0.8.7"])
  spec.add_development_dependency('ruby-debug', [">= 0.10"])
  spec.add_development_dependency('rspec', ["~> 2.5"])
  spec.add_development_dependency('flexmock', ["~> 0.9"])
  spec.add_development_dependency("actionmailer", ["~> 2.3.5"])
  #spec.add_development_dependency('right_agent', :git => 'git@github.com:rightscale/right_support.git')

  spec.description = <<-EOF
  RightInfrastructureAgent provides the foundation for RightScale infrastructure
  servers that connect into the RightScale system via the RabbitMQ message bus.
  It extends RightAgent in configuration, monitoring, and packet handling areas
  as needed generically by infrastructure servers.
EOF

  candidates = Dir.glob("{lib,spec}/**/*") +
               ["LICENSE", "README.rdoc", "Rakefile", "right_infrastructure_agent.gemspec"]
  spec.files = candidates.sort
end
