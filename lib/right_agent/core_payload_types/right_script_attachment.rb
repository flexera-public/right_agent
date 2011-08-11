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
#

require 'digest/sha1'
require 'uri'

module RightScale

  # RightScript attachment
  class RightScriptAttachment

    include Serializable

    # (String) S3 attachment URL
    attr_accessor :url

    # (String) Attachment file name
    attr_accessor :file_name

    # (String) Cache identifier
    attr_accessor :etag

    # (Binary string) Repose token for attachment
    attr_accessor :token

    # (String) Content digest
    attr_accessor :digest

    def initialize(*args)
      @url       = args[0] if args.size > 0
      @file_name = args[1] if args.size > 1
      @etag      = args[2] if args.size > 2
      @token     = args[3] if args.size > 3
      @digest    = args[4] if args.size > 4
    end

    # Array of serialized fields given to constructor
    def serialized_members
      [ @url, @file_name, @etag, @token, @digest ]
    end

    # Return the Repose hash for this attachment.
    def to_hash
      RightScriptAttachment.hash_for(@url, @file_name, @etag)
    end

    # Fill out the session cookie appropriately for this attachment.
    def fill_out(session)
      session['scope'] = "attachments"
      if @digest
        session['resource'] = @digest
      else
        session['resource'] = to_hash
        session['url'] = @url
        session['etag'] = @etag
      end
      @token = session.to_s
    end

    # Return the Repose hash for the given URL/filename/ETag triple.
    #
    # === Parameters
    # url(String):: URL to request
    # filename(String):: local filename
    # etag(String):: expected ETag
    #
    # === Return
    # String:: hashed token suitable for communicating to Repose
    def self.hash_for(url, filename, etag)
      uri = URI::parse(url).dup
      uri.query = nil
      Digest::SHA1.hexdigest("#{uri}\000#{etag}")
    end
  end
end
