#
# Copyright (c) 2012 RightScale Inc
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

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))

describe "RightScale::DispatchedCache" do

  include FlexMock::ArgumentTypes

  before(:each) do
    flexmock(RightScale::Log).should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    flexmock(RightScale::Log).should_receive(:info).by_default
    @now = Time.at(1000000)
    flexmock(Time).should_receive(:now).and_return(@now).by_default
    @agent_id = "rs-agent-1-1"
    @cache = RightScale::DispatchedCache.new(@agent_id)
    @token1 = "token1"
    @token2 = "token2"
    @token3 = "token3"
  end

  context "initialize" do

    it "should initialize cache" do
      @cache.instance_variable_get(:@cache).should == {}
      @cache.instance_variable_get(:@lru).should == []
    end

    it "should initialize agent identity" do
      @cache.instance_variable_get(:@identity).should == @agent_id
    end

  end

  context "store" do

    it "should store request token" do
      @cache.store(@token1)
      @cache.instance_variable_get(:@cache)[@token1].should == @now.to_i
      @cache.instance_variable_get(:@lru).should == [@token1]
    end

    it "should update lru list when store to existing entry" do
      @cache.store(@token1)
      @cache.instance_variable_get(:@cache)[@token1].should == @now.to_i
      @cache.instance_variable_get(:@lru).should == [@token1]
      @cache.store(@token2)
      @cache.instance_variable_get(:@cache)[@token2].should == @now.to_i
      @cache.instance_variable_get(:@lru).should == [@token1, @token2]
      flexmock(Time).should_receive(:now).and_return(@now += 10)
      @cache.store(@token1)
      @cache.instance_variable_get(:@cache)[@token1].should == @now.to_i
      @cache.instance_variable_get(:@lru).should == [@token2, @token1]
    end

    it "should remove old cache entries when store new one" do
      @cache.store(@token1)
      @cache.store(@token2)
      @cache.instance_variable_get(:@cache).keys.should =~ [@token1, @token2]
      @cache.instance_variable_get(:@lru).should == [@token1, @token2]
      flexmock(Time).should_receive(:now).and_return(@now += RightScale::DispatchedCache::MAX_AGE + 1)
      @cache.store(@token3)
      @cache.instance_variable_get(:@cache).keys.should == [@token3]
      @cache.instance_variable_get(:@lru).should == [@token3]
    end

    it "should not store anything if token is nil" do
      @cache.store(nil)
      @cache.instance_variable_get(:@cache).should be_empty
      @cache.instance_variable_get(:@lru).should be_empty
    end

  end

  context "serviced_by" do

    it "should return who request was serviced by and make it the most recently used" do
      @cache.store(@token1)
      @cache.store(@token2)
      @cache.instance_variable_get(:@lru).should == [@token1, @token2]
      @cache.serviced_by(@token1).should == @agent_id
      @cache.instance_variable_get(:@lru).should == [@token2, @token1]
    end

    it "should return nil if request was not previously serviced" do
      @cache.serviced_by(@token1).should be_nil
      @cache.store(@token1)
      @cache.serviced_by(@token1).should == @agent_id
      @cache.serviced_by(@token2).should be_nil
    end

  end

  context "stats" do

    it "should return nil if cache empty" do
      @cache.stats.should be_nil
    end

    it "should return total and max age" do
      @cache.store(@token1)
      flexmock(Time).should_receive(:now).and_return(@now += 10)
      @cache.store(@token2)
      @cache.stats.should == {
        "local total" => 2,
        "local max age" => "10 sec"
      }
      @cache.serviced_by(@token1)
      @cache.stats.should == {
        "local total" => 2,
        "local max age" => "0 sec"
      }
    end

  end

end # RightScale::Dispatcher
