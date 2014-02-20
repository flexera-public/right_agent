# -*-ruby-*-
# Copyright: Copyright (c) 2011-2013 RightScale, Inc.
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
require 'rbconfig'

Gem::Specification.new do |spec|
  spec.name      = 'right_agent'
  spec.version   = '2.0.4'
  spec.date      = '2014-02-20'
  spec.authors   = ['Lee Kirchhoff', 'Raphael Simon', 'Tony Spataro', 'Scott Messier']
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
  spec.add_dependency('rest-client', '1.7.0.alpha')
  spec.add_dependency('faye-websocket', '0.7.0')
  spec.add_dependency('eventmachine', ['>= 0.12.10', '< 2.0'])
  spec.add_dependency('net-ssh', '~> 2.0')

  # TEAL HACK: rake gem may override current RUBY_PLATFORM to allow building
  # gems for all supported platforms from any platform. rubygems 1.8.x makes it
  # necessary to produce platform-specific gems with context-sensitive gemspecs
  # in order to retain Windows (or Linux)-specific gem requirements. this works
  # from any platform because there is no native code to pre-compile and package
  # with this gem.
  gem_platform = defined?(::RightScale::MultiPlatformGemTask.gem_platform_override) ?
    ::RightScale::MultiPlatformGemTask.gem_platform_override :
    nil
  gem_platform ||= ::RbConfig::CONFIG['host_os']
  case gem_platform
  when /mswin/i
    spec.add_dependency('win32-api', ['>= 1.4.5', '< 1.4.7'])
    spec.add_dependency('win32-dir', '~> 0.3.5')
    spec.add_dependency('win32-process', '~> 0.6.1')
    spec.add_dependency('msgpack', ['>= 0.4.4', '< 0.5'])
    spec.add_dependency('json', '1.4.6')
    spec.platform = 'x86-mswin32-60'
  when /mingw/i
    spec.add_dependency('ffi')
    spec.add_dependency('win32-dir', '>= 0.3.5')
    spec.add_dependency('win32-process', '>= 0.6.1')
    spec.add_dependency('msgpack', ['>= 0.4.4', '< 0.6'])
    spec.add_dependency('json', '~> 1.4')
    spec.platform = 'x86-mingw32'
  when /win32|dos|cygwin|windows/i
    raise ::NotImplementedError, 'Unsupported Ruby-on-Windows variant'
  else
    # ffi is not currently needed by Linux but it does no harm to have it and it
    # allows bundler to generate a consistent Gemfile.lock when it is declared
    # for both mingw and Linux.
    spec.add_dependency('ffi')
    spec.add_dependency('msgpack', ['>= 0.4.4', '< 0.6'])
    spec.add_dependency('json', '~> 1.4')
  end

  spec.description = <<-EOF
RightAgent provides a foundation for running an agent on a server to interface
in a secure fashion with other agents in the RightScale system using RightNet,
which operates in either HTTP or AMQP mode. When using HTTP, RightAgent
makes requests to RightApi servers and receives requests using long-polling or
WebSockets via the RightNet router. To respond to requests it posts to the
HTTP router. When using AMQP, RightAgent uses RabbitMQ as the message bus and
the RightNet router as the routing node to make requests; to receives requests
routed to it by the RightNet router, it establishes a queue on startup. The
packets are structured to invoke services in the agent represented by actors
and methods. The RightAgent may respond to these requests with a result packet
that the router then routes to the originator.
EOF

  candidates = Dir.glob("{lib,spec}/**/*") +
               ["LICENSE", "README.rdoc", "Rakefile", "right_agent.gemspec"]
  spec.files = candidates.sort
end
