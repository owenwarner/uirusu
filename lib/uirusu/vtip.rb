# Copyright (c) 2012-2013 Arxopia LLC.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# Neither the name of the project's author nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'net/http'
require 'uri'

module Uirusu
	#
	#
	module VTIP
		REPORT_URL = Uirusu::VT_API + "/ip-address/report?"

		# Searches reports by IP from Virustotal.com
		#
		# @param api_key Virustotal.com API key
		# @param resource url to search
		#
		# @return [JSON] Parsed response
		def self.query_report(api_key, ip)
			if api_key == nil
				raise "Invalid API Key"
			end

			if ip == nil
				raise "Invalid resource, must be a valid IP"
			end

      url = REPORT_URL + "ip=#{ip}&apikey=#{api_key}"
      response = Net::HTTP.get_response(URI.parse(url))

      begin
        case response.code
          when "429", "204"
            raise "Virustotal limit reached. Try again later."
          when "403"
            raise "Invalid privileges, please check your API key."
          when "200"
            JSON.parse(response.body)
          else
            raise "Unknown Server error."
        end
      rescue RestClient::Exception => e
        raise "Error: #{e}"
      end
		end
	end
end

