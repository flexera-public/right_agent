#
# Copyright (c) 2009-2013 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require ::File.expand_path('../../spec_helper', __FILE__)

# reloads the Platform overrides for the current platform under test and then
# restores the default platform to avoid breaking subsequent spec tests. works
# because each implementation is expected to fully override the methods in the
# base Platform class and so support multiple redefinition.
#
# requires the following to be defined by spec in a platform-specific manner:
#  instrument_booted_at
module PlatformSpecHelper

  # references mocked Platform class and instance to simplify singleton testing.
  attr_reader :file_class, :platform_class, :platform_instance

  # resets the Platform singleton.
  def reset_platform_singleton
    # release any existing singleton to force full reload from source.
    ::RightScale::Platform.instance_variable_set(:@singleton__instance__, nil)
    true
  end

  # Invoke within a before(:all) in described class.
  def before_all_platform_tests
    return true if RUBY_VERSION =~ /^1\.8/  # see below

    reset_platform_singleton

    # redefine Platform#initialize_platform_specific to defeat load-upon-
    # initialize behavior of singleton and give us a chance to set genus/species
    # explicitly before any loading occurs.
    ::RightScale::Platform.class_eval('def initialize_platform_specific; end')

    instance = ::RightScale::Platform.instance
    instance.instance_variable_set(:@genus, expected_genus)
    instance.instance_variable_set(:@species, expected_species)

    # invoke require logic for load-once behavior.
    unless instance.send(:load_platform_specific)
      # forcibly reload platform under test when require returns false.
      load instance.send(:platform_base_path) + '.rb'
      load instance.send(:platform_genus_path) + '.rb'
      load instance.send(:platform_species_path) + '.rb'
    end
    ::RightScale::Platform.genus.should == expected_genus
    ::RightScale::Platform.species.should == expected_species
    true
  end

  # Invoke within a after(:all) in described class.
  def after_all_platform_tests
    return true if RUBY_VERSION =~ /^1\.8/  # see below

    # 'restore' original singleton. this does not undefine any additional nested
    # classes that are platform-specific (for other than the current platform)
    # but they will not be invoked and so are harmless.
    reset_platform_singleton
    instance = ::RightScale::Platform.instance
    load instance.send(:platform_base_path) + '.rb'
    load instance.send(:platform_genus_path) + '.rb'
    load instance.send(:platform_species_path) + '.rb'
    instance.send(:initialize_genus)
    instance.send(:initialize_species)
    true
  end

  # Invoke within a before(:each) in described class.
  def before_each_platform_test
    # TEAL FIX might be that flexmock version is too new for ruby 1.8 to work,
    # but not really important going forward.
    if RUBY_VERSION =~ /^1\.8/
      pending 'before(:all) mocks do not work in ruby 1.8'
    end

    # reset singleton again but no need to reload platform code at this point.
    # the issue is that flexmock needs a fresh instance to mock out each time or
    # else the mock teardown goes haywire and spews meaningless stack-traces to
    # the console. the problem seems to be exacerbated by these tests redefining
    # methods of Platform (out of necessity).
    reset_platform_singleton
    platform = ::RightScale::Platform
    instance = platform.instance
    instance.instance_variable_set(:@genus, expected_genus)
    instance.instance_variable_set(:@species, expected_species)

    # create mocks.
    @file_class = flexmock(::File)
    @platform_class = flexmock(platform)
    @platform_instance = flexmock(instance)

    # require normalize_path to be mocked during spec runs as it actually
    # invokes APIs on Windows.
    file_class.should_receive(:normalize_path).and_return do |*args|
      raise ::NotImplementedError, "Must mock all calls to File.normalize_path: #{args.inspect}"
    end.by_default

    # defeat any shell execution by default (i.e. until properly mocked).
    platform_class.should_receive(:execute).and_return do |*args|
      raise ::NotImplementedError, "Must mock all calls to Platform.execute for class: #{args.inspect}"
    end.by_default
    platform_instance.should_receive(:execute).and_return do |*args|
      raise ::NotImplementedError, "Must instrument all calls to Platform#execute for instance: #{args.inspect}"
    end.by_default
    ::RightScale::Platform.genus.should == expected_genus
    ::RightScale::Platform.species.should == expected_species
    expect { ::RightScale::Platform.execute(nil) }.to raise_error(::NotImplementedError)
    expect { ::RightScale::Platform.instance.execute(nil) }.to raise_error(::NotImplementedError)
    true
  end

  # Invoke within a after(:each) in described class.
  def after_each_platform_test
    @file_class = nil
    @platform_class = nil
    @platform_instance = nil
    true
  end

end # PlatformSpecHelper

shared_examples_for 'supports any platform shell' do
  let(:minimum_uptime)     { 10 * 60 }
  let(:expected_booted_at) { ::Time.now.to_i - minimum_uptime }

  # Sleeps until timer ticks over. Note that sleep(1) does not guarantee
  # a tick-over and it may take sleep(< 1) to observe the tick-over.
  def wait_for_tick_change
    start_tick = ::Time.now.to_i
    while ::Time.now.to_i == start_tick
      sleep 0.1
    end
    true
  end

  context '#format_redirect_stdout' do
    it 'should format redirect of stdout' do
      subject.format_redirect_stdout('foo bar').
        should == "foo bar 1>#{subject.null_output_name}"
      subject.format_redirect_stdout('bar foo', '/tmp/foo').
        should == 'bar foo 1>/tmp/foo'
    end
  end # format_redirect_stdout

  context '#format_redirect_stderr' do
    it 'should format redirect of stderr' do
      subject.format_redirect_stderr('foo bar').
        should == "foo bar 2>#{subject.null_output_name}"
      subject.format_redirect_stderr('bar foo', '/tmp/foo').
        should == 'bar foo 2>/tmp/foo'
    end
  end # format_redirect_stderr

  context '#format_redirect_both' do
    it 'should format redirect of stderr' do
      subject.format_redirect_both('foo bar').
        should == "foo bar 1>#{subject.null_output_name} 2>&1"
      subject.format_redirect_both('bar foo', '/tmp/foo').
        should == 'bar foo 1>/tmp/foo 2>&1'
    end
  end # format_redirect_both

  context '#uptime' do
    it 'should be positive' do
      instrument_booted_at(expected_booted_at) { minimum_uptime }
      subject.uptime.should >= minimum_uptime
    end

    it 'should be strictly increasing' do
      uptime = minimum_uptime
      instrument_booted_at(expected_booted_at) { uptime }
      u0 = subject.uptime
      wait_for_tick_change  # uptime may use either system data or a relative time
      uptime += 1
      u1 = subject.uptime
      (u1 - u0).should > 0.0
    end
  end # uptime

  context '#booted_at' do
    it 'should be some time in the past' do
      instrument_booted_at(expected_booted_at) { minimum_uptime }
      subject.booted_at.should == expected_booted_at
    end

    it 'should be constant' do
      uptime = minimum_uptime
      instrument_booted_at(expected_booted_at) { uptime }
      b0 = subject.booted_at
      wait_for_tick_change  # uptime may use either system data or a relative time
      uptime += 1
      b1 = subject.booted_at
      b0.should == b1
    end
  end # booted_at
end # supports any platform shell
