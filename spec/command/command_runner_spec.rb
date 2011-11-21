#
# Copyright (c) 2009-2011 RightScale Inc
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

require File.expand_path(File.join(File.dirname(__FILE__), '..', 'spec_helper'))

module RightScale

  class CommandIOMock < CommandIO

    include Singleton

    def trigger_listen(payload)
      @test_callback.call(payload)
    end

    def listen(socket_port, &block)
      @test_callback = block
      true
    end

  end

end

describe RightScale::CommandRunner do

  before(:all) do
    @command_payload = { :name => 'test', :options => 'options' }
    @socket_port = TEST_SOCKET_PORT
  end

  context :start do
    before(:each) do
      @pid_file = flexmock(RightScale::PidFile)
      @pid_file.should_receive(:exists?).and_return(true)
      @pid_file.should_receive(:set_command_options).and_return(true)
      flexmock(RightScale::PidFile).should_receive(:new).and_return(@pid_file)
    end

    context 'when a block is provided' do
      before(:each) do
        @block = Proc.new do |pid_file|
          @callback_pid_file = pid_file
        end
      end

      it 'should yield its PidFile' do
        commands = { :test => lambda { |opt, _| } }
        flexmock(RightScale::CommandIO).should_receive(:instance).and_return(RightScale::CommandIOMock.instance)
        RightScale::CommandRunner.start(@socket_port, RightScale::AgentIdentity.generate, commands, &@block)
        @callback_pid_file.should == @pid_file
      end
    end
  end

  it 'should handle invalid formats' do
    flexmock(RightScale::CommandIO.instance).should_receive(:listen).and_yield(['invalid yaml'])
    flexmock(RightScale::Log).should_receive(:info).once
    RightScale::CommandRunner.start(@socket_port, RightScale::AgentIdentity.generate, commands={})
  end

  it 'should handle non-existent commands' do
    flexmock(RightScale::CommandIO.instance).should_receive(:listen).and_yield(@command_payload)
    flexmock(RightScale::Log).should_receive(:info).once
    RightScale::CommandRunner.start(@socket_port, RightScale::AgentIdentity.generate, commands={})
  end

  it 'should run commands' do
    commands = { :test => lambda { |opt, _| @opt = opt } }
    flexmock(RightScale::CommandIO).should_receive(:instance).and_return(RightScale::CommandIOMock.instance)
    cmd_options = RightScale::CommandRunner.start(@socket_port, RightScale::AgentIdentity.generate, commands)
    payload = @command_payload.merge(cmd_options)
    RightScale::CommandIOMock.instance.trigger_listen(payload)
    @opt.should == payload
  end

end
