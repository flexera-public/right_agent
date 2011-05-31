require 'rspec/core/rake_task'
require 'fileutils'

# Usage (rake --tasks):
#
# rake spec               # Run all specs in all specs directories
# rake spec:clobber_rcov  # Remove rcov products for rcov
# rake spec:doc           # Print Specdoc for all specs
# rake spec:rcov          # Run all specs all specs directories with RCov

RIGHT_BOT_ROOT = File.dirname(__FILE__)

# Allows for debugging of order of spec files by reading a specific ordering of
# files from a text file, if present. all too frequently, success or failure
# depends on the order in which tests execute.
RAKE_SPEC_ORDER_FILE_PATH = ::File.join(RIGHT_BOT_ROOT, "rake_spec_order_list.txt")

# Setup path to spec files and spec options
#
# === Parameters
# t(RSpec::Core::RakeTask):: Task instance to be configured
#
# === Return
# t(RSpec::Core::RakeTask):: Configured task
def setup_spec(t)
  t.rspec_opts = ['--options', "\"#{RIGHT_BOT_ROOT}/spec/spec.opts\""]

  # optionally read or write spec order for debugging purposes. use a stubbed
  # file with the text "FILL ME" to get the spec ordering for the current
  # machine.
  if ::File.file?(RAKE_SPEC_ORDER_FILE_PATH)
    if ::File.read(RAKE_SPEC_ORDER_FILE_PATH).chomp == "FILL ME"
      ::File.open(RAKE_SPEC_ORDER_FILE_PATH, "w") do |f|
        f.puts t.spec_files.to_a.join("\n")
      end
    else
      t.spec_files = FileList.new
      ::File.open(RAKE_SPEC_ORDER_FILE_PATH, "r") do |f|
        while (line = f.gets) do
          line = line.chomp
          (t.spec_files << line) if not line.empty?
        end
      end
    end
  end
  t
end

# Default to running unit tests
task :default => :spec

# List of tasks
desc 'Run all specs in all specs directories'
RSpec::Core::RakeTask.new(:spec) do |t|
  setup_spec(t)
end

namespace :spec do
  desc 'Run all specs all specs directories with RCov'
  RSpec::Core::RakeTask.new(:rcov) do |t|
    setup_spec(t)
    t.rcov = true
    t.rcov_opts = lambda { IO.readlines("#{RIGHT_BOT_ROOT}/spec/rcov.opts").map {|l| l.chomp.split ' '}.flatten }
  end

  desc 'Print Specdoc for all specs (excluding plugin specs)'
  RSpec::Core::RakeTask.new(:doc) do |t|
    setup_spec(t)
    t.spec_opts = ['--format', 'specdoc', '--dry-run']
  end
end
