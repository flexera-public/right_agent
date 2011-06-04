# Monkey-patch the JSON gem's load/dump interface to avoid
# the clash between ActiveRecord's Hash#to_json and
# the gem's Hash#to_json.
module JSON
  class <<self
    def dump(obj)
      ActiveSupport::JSON.encode(obj)
    end
  end
end

# an empty proxy actor, we need it's request method in the core
class Proxy
  include RightScale::Actor

end
