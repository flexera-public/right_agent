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
  spec.version   = '1.0.0'
  spec.date      = '2013-10-07'
  spec.authors   = ['Lee Kirchhoff', 'Raphael Simon', 'Tony Spataro']
  spec.email     = 'lee@rightscale.com'
  spec.homepage  = 'https://github.com/rightscale/right_agent'
  spec.platform  = Gem::Platform::RUBY
  spec.summary   = 'Agent for interfacing server with RightScale system'
  spec.has_rdoc  = true
  spec.rdoc_options = ["--main", "README.rdoc", "--title", "RightAgent"]
  spec.extra_rdoc_files = ["README.rdoc"]
  spec.required_ruby_version = '>= 1.8.7'
  spec.require_path = 'lib'

  spec.add_dependency('right_support', ['>= 2.4.1', '< 3.0'])
  spec.add_dependency('right_amqp', '~> 0.7')
  spec.add_dependency('eventmachine', ['>= 0.12.10', '< 2.0'])
  spec.add_dependency('net-ssh', '~> 2.0')

  msgpack_constraint = ['>= 0.4.4', '< 0.6']
  json_constraint = ['>= 1.4', '<= 1.7.6'] # json_create behavior change in 1.7.7
  case RUBY_PLATFORM
  when /mswin/i
    msgpack_constraint = '0.4.4'  # last tested native mswin prebuilt gem
    json_constraint = '1.4.6'     # end-of-life native mswin prebuilt gem
    spec.add_dependency('win32-api', '1.4.5')
    spec.add_dependency('win32-dir', '0.3.7')
    spec.add_dependency('win32-process', '0.6.5')
    spec.add_dependency('windows-pr', '1.2.1')
  when /mingw/i
    spec.add_dependency('ffi', '~> 1.9.0')
    spec.add_dependency('win32-dir', '~> 0.4.6')
    spec.add_dependency('win32-process', '~> 0.7.3')
  when /win32|dos|cygwin/i
    raise ::NotImplementedError, 'Unsupported Ruby-on-Windows variant'
  end
  spec.add_dependency('msgpack', msgpack_constraint)
  spec.add_dependency('json', json_constraint)

  spec.description = <<-EOF
RightAgent provides a foundation for running an agent on a server to interface
in a secure fashion with other agents in the RightScale system. A RightAgent
uses RabbitMQ as the message bus and the RightScale mapper as the routing node.
Servers running a RightAgent establish a queue on startup for receiving packets
routed to it via the mapper. The packets are structured to invoke services in
the agent represented by actors and methods. The RightAgent may respond to these
requests with a result packet that the mapper then routes to the originator.
EOF

  candidates = Dir.glob("{lib,spec}/**/*") +
               ["LICENSE", "README.rdoc", "Rakefile", "right_agent.gemspec"]
  spec.files = candidates.sort
end
