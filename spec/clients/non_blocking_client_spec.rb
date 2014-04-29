#--
# Copyright (c) 2013-2014 RightScale Inc
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
#++

require File.expand_path(File.join(File.dirname(__FILE__), 'spec_helper'))
require File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'lib', 'right_agent', 'clients', 'non_blocking_client'))

describe RightScale::NonBlockingClient do

  include FlexMock::ArgumentTypes

  before(:each) do
    @log = flexmock(RightScale::Log)
    @log.should_receive(:error).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @log.should_receive(:warning).by_default.and_return { |m| raise RightScale::Log.format(*m) }
    @url = "http://my.com"
    @urls = [@url]
    @host = @url
    @path = "/foo/bar"
    @balancer = flexmock("balancer")
    flexmock(RightSupport::Net::RequestBalancer).should_receive(:new).and_return(@balancer).by_default
    @later = (@now = Time.now)
    flexmock(Time).should_receive(:now).and_return { @later += 1 }
  end

  context :initialize do
    before(:each) do
      @options = {}
      @client = RightScale::NonBlockingClient.new(@options)
    end

    it "does not initialize use of proxy if not defined in environment" do
      @client.instance_variable_get(:@proxy).should be nil
    end

    ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY'].each do |proxy|
      context "when #{proxy} defined in environment" do
        after(:each) do
          ENV.delete(proxy)
        end

        it "initializes use of proxy" do
          ENV[proxy] = "https://my.proxy.com"
          @client = RightScale::NonBlockingClient.new(@options)
          @client.instance_variable_get(:@proxy).should == {:host => "my.proxy.com", :port => 443}
        end

        it "infers http scheme for proxy address" do
          ENV[proxy] = "1.2.3.4"
          @client = RightScale::NonBlockingClient.new(@options)
          @client.instance_variable_get(:@proxy).should == {:host => "1.2.3.4", :port => 80}
        end

        it "applies user and password to proxy address if defined in proxy address" do
          ENV[proxy] = "https://111:secret@my.proxy.com"
          @client = RightScale::NonBlockingClient.new(@options)
          @client.instance_variable_get(:@proxy).should == {:host => "my.proxy.com", :port => 443, :authorization => ["111", "secret"]}
        end
      end
    end

    it "constructs health check proc" do
      @client.health_check_proc.should be_a Proc
    end

    context "health check proc" do
      it "removes user and password from URL when checking health" do
        @url = "http://111:secret@me.com"
        @client = RightScale::NonBlockingClient.new(@options.merge(:health_check_path => "/health-check-me"))
        flexmock(@client).should_receive(:request).with(:get, "", "http://me.com", Hash, {:path => "/health-check-me"}).once
        @client.health_check_proc.call(@url)
      end

      it "uses default path if none specified" do
        flexmock(@client).should_receive(:request).with(:get, "", @host, Hash, {:path => "/health-check"}).once
        @client.health_check_proc.call(@url)
      end

      it "appends health check path to any existing path" do
        @url = "http://my.com/foo"
        flexmock(@client).should_receive(:request).with(:get, "", @host, Hash, {:path => "/foo/health-check"}).once
        @client.health_check_proc.call(@url)
      end

      it "uses fixed timeout values" do
        @client = RightScale::NonBlockingClient.new(@options.merge(:open_timeout => 5, :request_timeout => 30))
        connect_options = {:connect_timeout => 2, :inactivity_timeout => 5}
        flexmock(@client).should_receive(:request).with(:get, "", @host, connect_options, Hash).once
        @client.health_check_proc.call(@url)
      end

      it "sets API version if specified" do
        @client = RightScale::NonBlockingClient.new(@options.merge(:api_version => "2.0"))
        request_options = {:path => "/health-check", :head => {"X-API-Version" => "2.0"}}
        flexmock(@client).should_receive(:request).with(:get, "", @host, Hash, request_options).once
        @client.health_check_proc.call(@url)
      end

      it "uses proxy if defined" do
        ENV["HTTPS_PROXY"] = "https://my.proxy.com"
        @client = RightScale::NonBlockingClient.new(@options)
        connect_options = {:connect_timeout => 2, :inactivity_timeout => 5, :proxy => {:host => "my.proxy.com", :port => 443}}
        flexmock(@client).should_receive(:request).with(:get, "", @host, connect_options, Hash).once
        @client.health_check_proc.call(@url)
        ENV.delete("HTTPS_PROXY")
      end
    end
  end

  context :options do
    before(:each) do
      @options = {}
      @verb = :get
      @params = {}
      @headers = {}
      @client = RightScale::NonBlockingClient.new(@options)
    end

    it "sets default open and request timeouts" do
      connect_options, _ = @client.options(@verb, @path, @params, @headers, @options)
      connect_options[:connect_timeout].should == RightScale::BalancedHttpClient::DEFAULT_OPEN_TIMEOUT
      connect_options[:inactivity_timeout].should == RightScale::BalancedHttpClient::DEFAULT_REQUEST_TIMEOUT
    end

    it "sets specified open and request timeouts" do
      @options = {:open_timeout => 1, :request_timeout => 2}
      connect_options, _ = @client.options(@verb, @path, @params, @headers, @options)
      connect_options[:connect_timeout].should == 1
      connect_options[:inactivity_timeout].should == 2
    end

    it "uses poll timeout instead of request timeout if defined" do
      @options = {:open_timeout => 1, :poll_timeout=> 2, :request_timeout => 3}
      connect_options, _ = @client.options(:poll, @path, @params, @headers, @options)
      connect_options[:connect_timeout].should == 1
      connect_options[:inactivity_timeout].should == 2
    end

    it "does not uses poll timeout if defined but not polling" do
      @options = {:open_timeout => 1, :poll_timeout=> 2, :request_timeout => 3}
      connect_options, _ = @client.options(@verb, @path, @params, @headers, @options)
      connect_options[:connect_timeout].should == 1
      connect_options[:inactivity_timeout].should == 3
    end

    it "sets :keepalive if this is a poll request" do
      _, request_options = @client.options(:poll, @path, @params, @headers, @options)
      request_options[:keepalive].should be true
    end

    it "sets request headers" do
      @headers = {:some => "header"}
      _, request_options = @client.options(@verb, @path, @params, @headers, @options)
      request_options[:head].should == @headers
    end

    it "sets :proxy if defined" do
      ENV["HTTPS_PROXY"] = "https://my.proxy.com"
      @client = RightScale::NonBlockingClient.new(@options)
      connect_options, _ = @client.options(@verb, @path, @params, @headers, @options)
      connect_options[:proxy].should == {:host => "my.proxy.com", :port => 443}
      ENV.delete("HTTPS_PROXY")
    end

    [:get, :delete].each do |verb|
      context "with #{verb.inspect}" do
        it "appends form-encoded query option to path" do
          @params = {:some => "data"}
          _, request_options = @client.options(verb, @path, @params, @headers, @options)
          request_options[:path].should == "/foo/bar?some=data"
          request_options[:body].should be nil
        end
      end
    end

    [:post, :put].each do |verb|
      context "with #{verb.inspect}" do
        it "stores JSON-encoded parameters in body" do
          @params = {:some => "data"}
          _, request_options = @client.options(verb, @path, @params, @headers, @options)
          request_options[:path].should == @path
          request_options[:body].should == JSON.dump(@params)
          request_options[:head][:content_type].should == "application/json"
        end
      end
    end
  end

  context "requesting" do
    before(:each) do
      @options = {}
      @connect_options = {:connect_timeout => 2, :inactivity_timeout => 5}
      @request_options = {:path => @path, :head => {:accept => "application/json"}}
      @result = {"out" => 123}
      @body = JSON.dump({:out => 123})
      @headers = EventMachine::HttpResponseHeader.new
      @headers.http_status = 200
      @headers["STATUS"] = "200 OK"
      @beautified_headers = {:status => "200 OK"}
      @response = flexmock("em http response", :response_header => @headers, :response => @body,
                           :error => nil, :errback => true, :callback => true).by_default
      @request = flexmock("em http request", :get => @response).by_default
      flexmock(EM::HttpRequest).should_receive(:new).and_return(@request).by_default
      @fiber = flexmock("fiber", :resume => true).by_default
      flexmock(Fiber).should_receive(:current).and_return(@fiber)
      flexmock(Fiber).should_receive(:yield).and_return([200, @body, @headers]).by_default
      @client = RightScale::NonBlockingClient.new(@options)
    end

    context :request do
      it "makes request" do
        @response.should_receive(:callback).and_yield.once
        @fiber.should_receive(:resume).with(200, @body, @headers).once
        flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
        @request.should_receive(:get).with(@request_options).and_return(@response).once
        @client.request(:get, @path, @host, @connect_options, @request_options)
        @client.connections[@path].should be nil
      end

      it "processes response and returns result plus response code, body, and headers" do
        @response.should_receive(:callback).and_yield.once
        @fiber.should_receive(:resume).with(200, @body, @headers).once
        flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
        result = @client.request(:get, @path, @host, @connect_options, @request_options)
        result.should == [@result, 200, @body, @beautified_headers]
      end

      it "handles host value that has path" do
        @response.should_receive(:callback).and_yield.once
        @fiber.should_receive(:resume).with(200, @body, @headers).once
        flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
        @request.should_receive(:get).with(on { |a| a[:path] == "/api" + @path }).and_return(@response).once
        @client.request(:get, @path, @host + "/api", @connect_options, @request_options)
        @request_options[:path].should == "/api/foo/bar"
      end

      it "converts connection errors to 500 by default" do
        @headers.http_status = 500
        @response.should_receive(:errback).and_yield.once
        @response.should_receive(:error).and_return(nil)
        @fiber.should_receive(:resume).with(500, "HTTP connection failure for GET").once
        flexmock(Fiber).should_receive(:yield).and_return([500, "HTTP connection failure for GET"]).once
        flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
        lambda { @client.request(:get, @path, @host, @connect_options, @request_options) }.
            should raise_error(RightScale::HttpExceptions::InternalServerError)
      end

      it "converts Errno::ETIMEDOUT error to 408 RequestTimeout" do
        @headers.http_status = 408
        @response.should_receive(:errback).and_yield.once
        @response.should_receive(:error).and_return(Errno::ETIMEDOUT)
        @fiber.should_receive(:resume).with(408, "Request timeout").once
        flexmock(Fiber).should_receive(:yield).and_return([408, "Request timeout"]).once
        flexmock(EM::HttpRequest).should_receive(:new).with(@host, @connect_options).and_return(@request).once
        lambda { @client.request(:get, @path, @host, @connect_options, @request_options) }.
            should raise_error(RightScale::HttpExceptions::RequestTimeout)
      end

      it "stores the connection if keepalive enabled" do
        @request_options.merge!(:keepalive => true)
        flexmock(EM::HttpRequest).should_receive(:new).and_return(@request).once
        @client.request(:get, @path, @host, @connect_options, @request_options)
        @client.connections[@path].should == {:host => @host, :connection => @request, :expires_at => @later + 5}
      end
    end

    context "polling" do
      before(:each) do
        @stop_at = @later + 10
        @request_options.merge!(:keepalive => true)
        @connection = {:host => @host, :connection => @request, :expires_at => @later}
      end

      context :poll do
        before(:each) do
          flexmock(Fiber).should_receive(:yield).and_return([200, @body, @headers]).once
        end

        it "polls using specified connection and returns result data" do
          @request.should_receive(:get).with(@request_options).and_return(@response).once
          result = @client.poll(@connection, @request_options, @stop_at)
          result.should be_a Array
          result[1].should == 200
        end

        it "handles host value that has path" do
          @connection[:host] += "/api"
          @request.should_receive(:get).with(on { |a| a[:path] == "/api" + @path }).and_return(@response).once
          @client.poll(@connection, @request_options, @stop_at)
        end

        it "beautifies response headers" do
          _, _, _, headers = @client.poll(@connection, @request_options, @stop_at)
          headers.should == @beautified_headers
        end

        it "processes the response to get the result" do
          result, _, _, _ = @client.poll(@connection, @request_options, @stop_at)
          result.should == @result
        end

        it "updates the timeout in the connection" do
          @client.poll(@connection, @request_options, @stop_at)
          @connection[:expires_at].should == @later + 5
        end
      end

      context :poll_again do
        it "makes HTTP get request using specified connection" do
          @client.send(:poll_again, @fiber, @request, @request_options, @stop_at).should be true
        end

        it "stops polling if there is a non-nil result" do
          @response.should_receive(:callback).and_yield.once
          @fiber.should_receive(:resume).with(200, @body, @headers).once
          @client.send(:poll_again, @fiber, @request, @request_options, @stop_at).should be true
        end

        it "stops polling if the status code is not 200" do
          @headers.http_status = 204
          @response.should_receive(:callback).and_yield.once
          @response.should_receive(:response).and_return(nil).once
          @fiber.should_receive(:resume).with(204, nil, @headers).once
          @client.send(:poll_again, @fiber, @request, @request_options, @stop_at).should be true
        end

        it "stops polling if it is time to" do
          @response.should_receive(:callback).and_yield.once
          @response.should_receive(:response).and_return(nil).once
          @fiber.should_receive(:resume).with(200, nil, @headers).once
          @client.send(:poll_again, @fiber, @request, @request_options, @later + 1).should be true
        end

        it "stops polling if there is an error" do
          @response.should_receive(:error).and_return("some error").once
          @response.should_receive(:errback).and_yield.once
          @fiber.should_receive(:resume).with(500, "some error").once
          @client.send(:poll_again, @fiber, @request, @request_options, @stop_at).should be true
        end

        it "otherwise polls again" do
          @response.should_receive(:callback).and_yield.twice
          @response.should_receive(:response).and_return(nil).once.ordered
          @response.should_receive(:response).and_return(@body).once.ordered
          @fiber.should_receive(:resume).once
          @client.send(:poll_again, @fiber, @request, @request_options, @later + 2).should be true
        end

        it "polls again for JSON-encoded nil result" do
          @response.should_receive(:callback).and_yield.twice
          @response.should_receive(:response).and_return("null").once.ordered
          @response.should_receive(:response).and_return(@body).once.ordered
          @fiber.should_receive(:resume).once
          @client.send(:poll_again, @fiber, @request, @request_options, @later + 2).should be true
        end
      end
    end

    context :close do
      it "closes all persistent connections" do
        @request_options.merge!(:keepalive => true)
        flexmock(EM::HttpRequest).should_receive(:new).and_return(@request).once
        @client.request(:get, @path, @host, @connect_options, @request_options)
        @request.should_receive(:close).with("terminating").once
        @client.connections.should_not be_empty
        @client.close("terminating").should be true
        @client.connections.should be_empty
      end
    end
  end

  context :handle_error do
    before(:each) do
      @options = {}
      @client = RightScale::NonBlockingClient.new(@options)
    end

    ["terminating", "reconnecting"].each do |error|
      it "converts #{error} error to a 200 OK" do
        @client.send(:handle_error, :get, error).should == [200, nil]
      end
    end

    it "converts Errno::ETIMEDOUT to 408 RequestTimeout" do
      @client.send(:handle_error, :get, Errno::ETIMEDOUT).should == [408, "Request timeout"]
    end

    it "converts error to 500 InternalServerError by default" do
      @client.send(:handle_error, :get, "failed").should == [500, "failed"]
    end

    it "generates error message for 500 InternalServerError if none specified" do
      @client.send(:handle_error, :get, nil).should == [500, "HTTP connection failure for GET"]
    end
  end

  context :beautify_headers do
    before(:each) do
      @client = RightScale::NonBlockingClient.new(@options)
    end

    it "beautifies header keys" do
      headers = {"SERVER" => "nginx/1.4.2", "DATE" => "Tue, 25 Mar 2014 22:19:52 GMT",
                 "CONTENT_TYPE" => "application/json; charset=utf-8", "CONTENT_LENGTH" => "4", "CONNECTION" => "close",
                 "STATUS" => "200 OK", "CACHE_CONTROL" => "private, max-age=0, must-revalidate", "X_RUNTIME" => "1", "SET_COOKIE" => ""}
      result = @client.send(:beautify_headers, headers)
      result.should == {:server => "nginx/1.4.2", :date => "Tue, 25 Mar 2014 22:19:52 GMT",
                 :content_type => "application/json; charset=utf-8", :content_length => "4", :connection => "close",
                 :status => "200 OK", :cache_control => "private, max-age=0, must-revalidate", :x_runtime => "1", :set_cookie => ""}
    end

    it "converts hyphenations to underscores" do
      @client.send(:beautify_headers, {"NON-BLOCKING" => "yes"}).should == {:non_blocking => "yes"}
    end
  end
end
