#
# Copyright (c) 2013 RightScale Inc
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

require 'stringio'

shared_examples_for 'supports unix platform filesystem' do

  context '#find_executable_in_path' do
    let(:path_env) { '/usr/local/bin:/usr/bin:/bin' }

    it 'should find executable' do
      mock_env = flexmock(::ENV)
      mock_env.should_receive(:[]).with('PATH').and_return(path_env)

      file_class.should_receive(:executable?).with('/usr/local/bin/foo').and_return(false).twice
      file_class.should_receive(:executable?).with('/usr/bin/foo').and_return(true).twice
      file_class.should_receive(:executable?).with('/usr/local/bin/bar').and_return(false).twice
      file_class.should_receive(:executable?).with('/usr/bin/bar').and_return(false).twice
      file_class.should_receive(:executable?).with('/bin/bar').and_return(false).twice

      subject.find_executable_in_path('foo').should == '/usr/bin/foo'
      subject.has_executable_in_path('foo').should be_true
      subject.find_executable_in_path('bar').should be_nil
      subject.has_executable_in_path('bar').should be_false
    end
  end # find_executable_in_path

  context 'paths' do
    it 'should return unix path constants' do
      subject.right_agent_cfg_dir.should == '/var/lib/rightscale/right_agent'
      subject.right_scale_static_state_dir.should == '/etc/rightscale.d'
      subject.right_link_static_state_dir.should == '/etc/rightscale.d/right_link'
      subject.right_link_dynamic_state_dir.should == '/var/lib/rightscale/right_link'
      subject.spool_dir.should == '/var/spool'
      subject.ssh_cfg_dir.should == '/etc/ssh'
      subject.cache_dir.should == '/var/cache'
      subject.log_dir.should == '/var/log'
      subject.source_code_dir.should == '/usr/src'
      subject.temp_dir.should == '/tmp'
      subject.pid_dir.should == '/var/run'
      subject.right_link_home_dir.should == '/opt/rightscale'
      subject.private_bin_dir.should == '/opt/rightscale/bin'
      subject.sandbox_dir.should == '/opt/rightscale/sandbox'
    end

    it 'should return unmodified paths from Windows compatibility methods' do
      path = '/tmp/some_path_to_test'
      subject.long_path_to_short_path(path).should == path
      subject.pretty_path(path, false).should == path
      subject.pretty_path(path, true).should == path
      subject.ensure_local_drive_path(path, 'foo').should == path
    end
  end # paths

  context '#create_symlink' do
    it 'should use ruby file to create symlink (under unix)' do
      file_class.should_receive(:symlink).with('/tmp/from', '/tmp/to').and_return(0)
      subject.create_symlink('/tmp/from', '/tmp/to').should == 0
    end
  end # create_symlink
end # supports unix platform filesystem

shared_examples_for 'supports unix platform shell' do
  it_should_behave_like 'supports any platform shell'

  context 'paths' do
    it 'should return path constants for unix' do
      subject.null_output_name.should == '/dev/null'
      subject.sandbox_ruby.should == '/opt/rightscale/sandbox/bin/ruby'
    end
  end # paths

  context 'commands' do
    it 'should return unmodified commands from Windows compatibility methods' do
      cmd = 'sh -c echo foo'
      subject.format_script_file_name(cmd).should == cmd
      subject.format_script_file_name(cmd, '.foo').should == cmd
    end

    [:format_executable_command, :format_shell_command].each do |methud|
      context methud do
        it 'should format commands' do
          subject.send(methud, 'foo').should == 'foo'
          subject.send(methud, 'bar', 'foo').should == 'bar foo'
          subject.send(methud, 'baz', 'a b', "c'd", 'foo').should == "baz \"a b\" \"c'd\" foo"
        end
      end # methud
    end # for each method (having identical behavior under unix)

    it 'should format ruby commands using sandbox ruby' do
      script_path = '/tmp/foo.rb'
      subject.format_ruby_command(script_path).should == '/opt/rightscale/sandbox/bin/ruby /tmp/foo.rb'
      subject.format_ruby_command(script_path, 'bar').should == '/opt/rightscale/sandbox/bin/ruby /tmp/foo.rb bar'
    end
  end # commands
end # supports unix platform shell

shared_examples_for 'supports unix platform rng' do
  context '#pseudorandom_bytes' do
    it 'should read requested byte length from urandom device under unix' do
      sio = StringIO.new
      buffer = 0.chr * 256
      256.times.each { |i| buffer[i] = i.chr }
      sio.write buffer
      sio.rewind
      file_class.should_receive(:open).with('/dev/urandom', 'r', Proc).and_yield(sio)
      subject.pseudorandom_bytes(16).should == buffer[0, 16]
      subject.pseudorandom_bytes(32).should == buffer[16, 32]
    end
  end # pseudorandom_bytes
end # supports unix platform rng

shared_examples_for 'supports unix platform process' do
  context '#resident_set_size' do
    it 'should return resident set size for current process' do
      cmd = "ps -o rss= -p #{$$}"
      platform_class.should_receive(:execute).with(cmd, {}).and_return('12345').once
      subject.resident_set_size.should == 12345
    end

    it 'should return resident set size for other process' do
      pid = 789
      cmd = "ps -o rss= -p #{pid}"
      platform_class.should_receive(:execute).with(cmd, {}).and_return('23456').once
      subject.resident_set_size(pid).should == 23456
    end
  end # pseudorandom_bytes
end # supports unix platform rng
