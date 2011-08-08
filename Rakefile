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
require 'fileutils'
require 'rake'
require 'rspec/core/rake_task'
require 'rake/rdoctask'
require 'rake/gempackagetask'
require 'rake/clean'

task :default => 'spec'

# == Gem packaging == #

desc "Package gem"
gemtask = Rake::GemPackageTask.new(Gem::Specification.load("right_agent.gemspec")) do |package|
  package.package_dir = ENV['PACKAGE_DIR'] || 'pkg'
  package.need_zip = true
  package.need_tar = true
end

directory gemtask.package_dir

CLEAN.include(gemtask.package_dir)

# == Unit tests == #

RSPEC_OPTS = ['--options', "\"#{File.dirname(__FILE__)}/spec/spec.opts\""]

desc 'Run unit tests'
RSpec::Core::RakeTask.new do |t|
  t.rspec_opts = RSPEC_OPTS
end

namespace :spec do
  desc 'Run unit tests with RCov'
  RSpec::Core::RakeTask.new(:rcov) do |t|
    t.rspec_opts = RSPEC_OPTS
    t.rcov = true
    t.rcov_opts = %q[--exclude "spec"]
  end

  desc 'Print Specdoc for all unit tests'
  RSpec::Core::RakeTask.new(:doc) do |t|
    t.rspec_opts = ["--format", "documentation"]
  end
end

# == Documentation == #

desc 'Generate API documentation to doc/rdocs/index.html'
Rake::RDocTask.new do |rd|
  rd.rdoc_dir = 'doc/rdocs'
  rd.main = 'README.rdoc'
  rd.rdoc_files.include 'README.rdoc', 'lib/**/*.rb'
end
CLEAN.include('doc/rdocs')

# == Emacs integration ==

desc 'Rebuild TAGS file for emacs'
task :tags do
  sh 'rtags -R lib spec'
end
