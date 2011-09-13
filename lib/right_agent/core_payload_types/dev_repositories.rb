#--
# Copyright: Copyright (c) 2010-2011 RightScale, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# 'Software'), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#++

module RightScale
  # Sequence of cookbooks to be checked out on the instance.
  class DevRepositories
    include Serializable

    attr_accessor :repositories

    # Initialize fields from given arguments
    def initialize(*args)
      @repositories = args[0] || {}
    end

    # Array of serialized fields given to constructor
    def serialized_members
      [ @repositories ]
    end

    # (Hash):: collection of repos to be checked out on the instance
    # :repo_sha (String):: the hash id (SHA) of the repository
    # :repo_detail (Hash):: info needed to checkout this repo
    #   {
    #     <Symbol> Type of repository: one of :git, :svn, :download or :local
    #       * :git denotes a 'git' repository that should be retrieved via 'git clone'
    #       * :svn denotes a 'svn' repository that should be retrieved via 'svn checkout'
    #       * :download denotes a tar ball that should be retrieved via HTTP GET (HTTPS if uri starts with https://)
    #       * :local denotes cookbook that is already local and doesn't need to be retrieved
    #     :repo_type => <Symbol>,
    #     <String> URL to repository (e.g. git://github.com/opscode/chef-repo.git)
    #     :url => <String>,
    #     <String> git commit or svn branch that should be used to retrieve repository
    #       Optional, use 'master' for git and 'trunk' for svn if tag is nil.
    #       Not used for raw repositories.
    #     :tag => <String>,
    #     <Array> Path to cookbooks inside repostory
    #       Optional (use location of repository as cookbook path if nil)
    #     :cookbooks_path => <Array>,
    #     <String> Private SSH key used to retrieve git repositories
    #       Optional, not used for svn and raw repositories.
    #     :ssh_key => <String>,
    #     <String> Username used to retrieve svn and raw repositories
    #       Optional, not used for git repositories.
    #     :username => <String>,
    #     <String> Password used to retrieve svn and raw repositories
    #       Optional, not used for git repositories.
    #     :password => <String>
    #  }
    # :cookbook_positions (Array):: List of CookbookPositions to be developed.  Represents the subset of cookbooks identified as the "dev cookbooks"
    def add_repo(repo_sha, repo_detail, cookbook_positions)
      @repositories ||= {}
      @repositories[repo_sha] = { :repo => repo_detail, :positions => cookbook_positions }
    end
  end
end

