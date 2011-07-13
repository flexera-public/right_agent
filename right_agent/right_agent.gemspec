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
  spec.name      = 'right_agent'
  spec.version   = '0.2.1'
  spec.authors   = ['Lee Kirchhoff', 'Raphael Simon']
  spec.email     = 'lee@rightscale.com'
  spec.homepage  = 'https://github.com/rightscale/right_agent'
  spec.platform  = Gem::Platform::RUBY
  spec.summary   = 'Agent for interfacing server with RightScale system'
  spec.has_rdoc  = true
  spec.rdoc_options = ["--main", "README.rdoc", "--title", "RightAgent"]
  spec.extra_rdoc_files = ["README.rdoc"]
  spec.required_ruby_version = '>= 1.8.7'
  spec.require_path = 'lib'

  spec.add_development_dependency('rake', [">= 0.8.7"])
  spec.add_development_dependency('ruby-debug', [">= 0.10"])
  spec.add_development_dependency('rspec', ["~> 2.5"])
  spec.add_development_dependency('flexmock', ["~> 0.9"])
  #spec.add_development_dependency('right_support', :git => 'git@github.com:rightscale/right_support.git')
  spec.add_development_dependency('amqp', "0.6.7")
  spec.add_development_dependency('json', [">= 1.4.4", "<= 1.4.6"])
  spec.add_development_dependency('msgpack', "0.4.4")
  spec.add_development_dependency('eventmachine', "0.12.10")

  spec.description = <<-EOF
  RightAgent provides a foundation for running an agent on a server to interface
  in a secure fashion with other agents in the RightScale system. A RightAgent
  uses RabbitMQ as the message bus and the RightScale mapper as the routing node.
  Servers running a RightAgent establish a queue on startup for receiving packets
  routed to it via the mapper. The packets are structured to invoke services in
  the agent represented by actors and methods. The RightAgent may respond to these
  requests with a result packet that the mapper then routes to the originator.
  Similarly a RightAgent can also make requests of other RightAgents in the
EOF

  candidates = Dir.glob("{lib,spec}/**/*") +
               ["LICENSE", "README.rdoc", "Rakefile", "right_agent.gemspec"]
  spec.files = candidates.sort
end
