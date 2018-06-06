# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/netsense"
require "base64"

describe LogStash::Filters::Netsense do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        netsense {
          target => "doc"
          fields => {
            "[message][args][command][sourceIEEEAddress]" => {"schema" => "H16" "key" => "sourceIEEEAddress" "items" => []}
            "[message][args][command][deviceId]" => {"schema" => "L>" "key" => "deviceId" "items" => []}
            "[message][args][command][data]" => {"schema" => "g*" "key" => "data" "items" => ["data0", "data1", "data2", "data3", "data4", "data5", "data6", "data7", "data8"]}
            "[message][args][command][sourceNetworkAddress]" => {"schema" => "C*" "key" => "sourceNetworkAddress"}
            "[message][args][command][pan_id]" => {"schema" => "H4" "key" => "panId" "items" => []}
          }
        }
      }
    CONFIG
    end

    sample("message" => { "args" => {
            "command" => {
                   "sourceIEEEAddress" => "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                            "deviceId" => "\x01\x80_\n",
                                "data" => "?\x80\x00\x00@\x00\x00\x00@@\x00\x00@\x80\x00\x00@\xA0\x00\x00@\xC0\x00\x00@\xE0\x00\x00A\x00\x00\x00A\x10\x00\x00",
                "sourceNetworkAddress" => "\xC0\xA8\x00g",
                              "pan_id" => "\x00\x00\x00\x00"
            }
          }
        }) do
      expect(subject.get("doc")).to eq({"data" => {"data8"=>9.0, "data7"=>8.0, "data6"=>7.0, "data5"=>6.0, "data4"=>5.0, "data3"=>4.0, "data2"=>3.0, "data1"=>2.0, "data0"=>1.0},
"deviceId" => 25190154,
"panId" => "0000",
"sourceIEEEAddress" => "0000000000000000",
"sourceNetworkAddress" => [192, 168, 0, 103]})
    end

    sample("massage" => "I love cupcake!") do
      expect(subject.get("doc")).to eq({})
    end
  end
end


