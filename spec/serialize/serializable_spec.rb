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
require 'json/ext'

class TestClass1

  include RightScale::Serializable

  attr_accessor :name, :array, :date

  def initialize(*args)
    @name  = args[0] if args.size > 0
    @array = args[1] if args.size > 1
    @date  = args[2] if args.size > 2
  end

  def serialized_members
    [@name, @array, @date]
  end
end

class TestClass2

  include RightScale::Serializable

  attr_accessor :attr1, :attr2

  def initialize(*args)
    attr1 = args[0]
    attr2 = args[1] if args.size > 1
  end

  def serialized_members
    [@attr1, @attr2]
  end

end

describe RightScale::Serializable do

  it 'should serialize using MessagePack' do
    a1 = TestClass1.new
    a1.name = "Test1"
    a1.array = ["some", "stuff" ]

    b1 = TestClass1.new
    b1.name = "Test2"
    b1.array = ["some", "more", "stuff"]

    c = TestClass2.new([a1, b1], 1234)
    a1.to_msgpack
    TestClass2.msgpack_create(c.to_msgpack).should == c
  end

  it 'should serialize using JSON' do
    a1 = TestClass1.new
    a1.name = "Test1"
    a1.array = ["some", "stuff" ]

    b1 = TestClass1.new
    b1.name = "Test2"
    b1.array = ["some", "more", "stuff"]

    c = TestClass2.new([a1, b1], 1234)
    a1.to_json
    TestClass2.json_create(c.to_msgpack).should == c
  end

end
