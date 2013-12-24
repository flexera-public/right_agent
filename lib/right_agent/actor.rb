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

module RightScale

  # This mixin provides agent actor functionality.
  #
  # To use it simply include it your class containing the functionality to be exposed:
  #
  #   class Foo
  #     include RightScale::Actor
  #     expose :bar
  #
  #     def bar(payload)
  #       # ...
  #     end
  #
  #   end
  module Actor

    # Callback invoked whenever Actor is included in another module or class.
    #
    # === Parameters
    # base(Module):: Module that included Actor module
    #
    # === Return
    # true:: Always return true
    def self.included(base)
      base.send :include, InstanceMethods
      base.extend(ClassMethods)
    end
    
    module ClassMethods

      # Construct default prefix by which actor is identified in requests
      #
      # === Return
      # prefix(String):: Default prefix
      def default_prefix
        prefix = to_s.to_const_path
      end

      # Add methods to list of services supported by actor and mark these methods
      # as idempotent
      #
      # === Parameters
      # methods(Array):: Symbol names for methods being exposed as actor idempotent services
      #
      # === Return
      # true:: Always return true
      def expose_idempotent(*methods)
        @exposed ||= {}
        methods.each do |m|
          if @exposed[m] == false
            Log.warning("Method #{m} declared both idempotent and non-idempotent, assuming non-idempotent")
          else
            @exposed[m] = true
          end
        end
        true
      end

      # Add methods to list of services supported by actor
      # By default these methods are not idempotent
      #
      # === Parameters
      # meths(Array):: Symbol names for methods being exposed as actor services
      #
      # === Return
      # true:: Always return true
      def expose_non_idempotent(*methods)
        @exposed ||= {}
        methods.each do |m|
          Log.warning("Method #{m} declared both idempotent and non-idempotent, assuming non-idempotent") if @exposed[m]
          @exposed[m] = false
        end
        true
      end

      alias :expose :expose_non_idempotent

      # Get /prefix/method paths that actor responds to
      #
      # === Parameters
      # prefix(String):: Prefix by which actor is identified in requests
      #
      # === Return
      # (Array):: /prefix/method strings
      def provides_for(prefix)
        return [] unless @exposed
        @exposed.each_key.select do |method|
          if instance_methods.include?(method.to_s) or instance_methods.include?(method.to_sym)
            true
          else
            Log.warning("Exposing non-existing method #{method} in actor #{prefix}")
            false
          end
        end.map { |method| "/#{prefix}/#{method}".squeeze('/') }
      end

      # Determine whether actor method is idempotent
      #
      # === Parameters
      # method(Symbol):: Name for actor method
      #
      # === Return
      # (Boolean):: true if idempotent, false otherwise
      def idempotent?(method)
        @exposed[method] if @exposed
      end

      # Set method called when dispatching to this actor fails
      #
      # The callback method is required to accept the following parameters:
      #   method(Symbol):: Actor method being dispatched to
      #   deliverable(Packet):: Packet delivered to dispatcher
      #   exception(Exception):: Exception raised
      #
      # === Parameters
      # proc(Proc|Symbol|String):: Procedure to be called on exception
      #
      # === Block
      # Block to be executed if no Proc provided
      #
      # === Return
      # @exception_callback(Proc):: Callback procedure
      def on_exception(proc = nil, &blk)
        raise 'No callback provided for on_exception' unless proc || blk
        @exception_callback = proc || blk
      end

      # Get exception callback procedure
      #
      # === Return
      # @exception_callback(Proc):: Callback procedure
      def exception_callback
        @exception_callback
      end
      
    end # ClassMethods     
    
    module InstanceMethods

      # Agents using actors are required to define a Sender class providing linkage
      # to a class that can perform the following send functions

      # Helper method to send a request to one or more targets with no response expected
      def send_push(*args)
        Sender.instance.send_push(*args)
      end

      # Helper method to send a request to a single target with a response expected
      # The request is retried if the response is not received in a reasonable amount of time
      # The request is allowed to expire per the agent's configured time-to-live, typically 1 minute
      def send_request(*args, &blk)
        Sender.instance.send_request(*args, &blk)
      end

    end # InstanceMethods
    
  end # Actor
  
end # RightScale
