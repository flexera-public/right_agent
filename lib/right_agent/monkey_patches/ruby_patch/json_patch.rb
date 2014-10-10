#
# Copyright (c) 2014 RightScale Inc
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

module JSON
  class << self
    def legacy_load(source)
      if source.respond_to? :to_str
        source = source.to_str
      elsif source.respond_to? :to_io
        source = source.to_io.read
      else
        source = source.read
      end
      source = source.dup.force_encoding("UTF-8") if source.respond_to?(:force_encoding)
      if source =~ /(.*)json_class":"Nanite::(.*)/
        source = Regexp.last_match(1) + 'json_class":"RightScale::' + Regexp.last_match(2)
      end
      # Workaround to make RightLink MessageEncoder work after chef update to 14.11
      # which uses ffi-yajl which monkey patch JSON module and decoding of serialazed Ruby objects
      # doesn't works as expected
      JSON.parser.new(source, JSON.load_default_options).parse
    end
  end
end
