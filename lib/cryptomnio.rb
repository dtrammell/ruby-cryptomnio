require 'rest-client'
require 'base64'
require 'json'

class Cryptomnio ## Cryptomnio Global Methods
	# Constants
	NAME        = "Cryptomnio Ruby Gem"
	AUTHOR      = "Dustin D. Trammell"
	GEM_VERSION = "0.0.1.pre"
	API_VERSION = "1.0.0"

	# Instance Variables

	def initalize
		puts "Cryptomnio Initalized" if DEBUG
	end
end

# HTTP Request Logging module for HTTPClient decoration
module LogHTTPRequest
	def get(url)
		puts "Sending Request for #{url}"
		super
	end
end

# HTTPClient Class Wrapper
class HTTPClient
	def initalize(client = RestClient)
		@client = client
	end

	def get(*args)
		@client.get(*args)
	end
end

# Cryptomnio REST Class
class Cryptomnio::REST < Cryptomnio # REST-specific Methods
	def initalize
		super
		# Get the HTTP proxy from the environment (if there is one)
		RestClient.proxy = EVN['http_proxy']
	end
end

# Cryptomnio REST Client Class
class Cryptomnio::REST::Client < Cryptomnio::REST # Cryptomnio REST Client
	attr_accessor :config

	def auth_basic
		# Create Authentication Header 
		@config[:auth_string] = "Basic %s" % Base64.urlsafe_encode64(@config[:username] + ":" + @config[:password])
		cryptomnio_header_auth = "Authorization: %s" % @config[:auth_string]
		puts cryptomnio_header_auth if DEBUG

		# Test Authentication
		payload = "Some API Call Here"
		res = RestClient.post( @config[:apiurl], payload, { :authorization => @auth_values } )
		return cryptomnio_header_auth
	end

	def upload_keys
		# If API key provided in config, upload and store it
		for cred in @config[:apikeys] do
			payload = {
				"exchange"   => cred[:exchange],
				"key"        => cred[:key],
				"secret"     => cred[:secret],
				"passphrase" => cred[:passphrase]
			}
			res = JSON.decode(RestClient.post( @config[:apiurl]+"/keys", JSON.generate(payload), { :authentication => @auth_values }, &block ))
			if res["code"] != "OK"
				raise "Cryptomnio Exchange Key for exchange %s storage failed." % payload["exchange"]
			end
		end
	end

	def initialize
		yield self if block_given?
		super


		# Store method config variables in an instance variable
		p @config if DEBUG
	end

end
