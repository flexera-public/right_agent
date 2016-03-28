#--  -*-ruby-*-
# Copyright: Copyright (c) 2010 RightScale, Inc.
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
#++

require 'rubygems'
require 'bundler/setup'

require 'rake'
require 'rubygems/package_task'
require 'rake/clean'
require 'rspec/core/rake_task'
require 'fileutils'

# These dependencies can be omitted using "bundle install --without"; tolerate their absence.
['rdoc/task'].each do |optional|
  begin
    require optional
  rescue LoadError
    # ignore
  end
end

spec_opts_file = "\"#{File.dirname(__FILE__)}/spec/spec.opts\""
spec_opts_file = "\"#{File.dirname(__FILE__)}/spec/spec.win32.opts\"" if RUBY_PLATFORM =~ /mingw|mswin32/
RSPEC_OPTS = ['--options', spec_opts_file]

desc "Run unit tests"
task :default => :spec

desc 'Run unit tests'
RSpec::Core::RakeTask.new do |t|
  t.pattern = Dir['**/*_spec.rb']
end

if defined?(Rake::RDocTask)
  desc 'Generate documentation for the right_agent gem.'
  Rake::RDocTask.new(:rdoc) do |rdoc|
    rdoc.rdoc_dir = 'doc'
    rdoc.title    = 'RightAgent'
    rdoc.options << '--line-numbers' << '--inline-source'
    rdoc.rdoc_files.include('README.rdoc')
    rdoc.rdoc_files.include('lib/**/*.rb')
    rdoc.rdoc_files.exclude('spec/**/*')
  end
end
CLEAN.include('doc')

module RightScale
  class MultiPlatformGemTask
    def self.gem_platform_override
      @gem_platform_override
    end

    def self.define(gem_platforms, spec_path, &callback)
      gem_platforms.each do |gem_platform|
        @gem_platform_override = gem_platform
        callback.call(::Gem::Specification.load(spec_path))
      end
    ensure
      @gem_platform_override = nil
    end
  end
end

# Multiply define gem and package task(s) using a gemspec with overridden gem
# platform value. This works because rake accumulates task actions instead of
# redefining them, so accumulated gem tasks will gem up all platforms. We need
# to produce multiple platform-specific .gem files because otherwise the gem
# dependencies for non-Linux platforms (i.e. Windows) are lost from the default
# .gem file produced on a Linux platform.
gemtask = nil
::RightScale::MultiPlatformGemTask.define(%w[linux mingw], 'right_agent.gemspec') do |spec|
  gemtask = Gem::PackageTask.new(spec) do |pkg|
    pkg.package_dir = 'pkg'

    # the following are used by 'package' task (but not by 'gem' task)
    pkg.need_zip = !`which zip`.strip.empty? # not present on Windows by default
    pkg.need_tar = true  # some form of tar is required on Windows and Linux
  end
end
CLEAN.include('pkg')

require 'right_develop'
RightDevelop::CI::RakeTask.new
