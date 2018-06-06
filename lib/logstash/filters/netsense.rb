# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/json"
require "logstash/timestamp"

class LogStash::Filters::Netsense < LogStash::Filters::Base
	config_name "netsense"
	config :target, :validate => :string
	config :fields, :validate => :hash, :required => true
	config :tag_on_failure, :validate => :array, :default => ["_netsenseparsefailure"]

	public
	def register
	end

	public
	def filter(event)
		@logger.debug? && @logger.debug("Running netsense filter", :event => event)
		parsed = {}
		@fields.each do |field, desc|
			source = event.get(field)
			if source and source.length > 0 and desc["schema"].kind_of? String and desc["key"].kind_of? String
				item = source.unpack(desc["schema"])
				if desc["items"].kind_of? Array
					if desc["items"].size == 0
						parsed[desc["key"]] = item[0]
					else
						parsed[desc["key"]] = {}
						desc["items"].each_with_index do |name, idx|
							parsed[desc["key"]][name] = item.fetch(idx, nil)
						end
					end
				else
					parsed[desc["key"]] = item
				end
			end
		end
		if @target
			event.set(@target, parsed)
		else
			parsed.each{|k, v| event.set(k, v)}
    end
    filter_matched(event)
	end
end