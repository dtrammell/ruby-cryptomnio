require 'rest-client'
require 'base64'
require 'json'

##
# This is the root Cryptomnio object Class.  It contains global constants

class Cryptomnio
	# Constants
	NAME        = "Cryptomnio Ruby Gem"
	AUTHOR      = "Dustin D. Trammell"
	GEM_VERSION = "0.0.1.pre"
	API_VERSION = "1.0.0"

	# Instance Variables

	##
	# Creates a new Cryptomnio object

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

##
# This is the root Cryptomnio REST object Class.
# 
# It inherets from the Cryptomnio object Class and contains REST-specific methods and variables.

class Cryptomnio::REST < Cryptomnio

	##
	# Creates a new Cryptomnio::REST object.
	#
	# If "http_proxy" is set in the program's environment, it will be used for
	# the RestClient's proxy setting.

	def initalize
		super
		# Get the HTTP proxy from the environment (if there is one)
		RestClient.proxy = EVN['http_proxy']
	end
end

##
# This is the Cryptomnio REST Client object Class
#
# It inherets from the Cryptomnio::REST object Class and contains REST Client-specific methods and variables.

class Cryptomnio::REST::Client < Cryptomnio::REST
	attr_accessor :config

	# Basic Authentication
	def auth_basic
		# Store Authentication string for Authorization Header in config
		@config[:auth_string] = "Basic %s" % Base64.urlsafe_encode64(@config[:username] + ":" + @config[:password])

		# DEBUG Output
		if DEBUG
			puts "Username: %s" % @config[:username]
			puts "Password: %s" % @config[:password]
			# TODO: Find better test call to use
			puts "Requesting: %s%s" % [ @config[:apiurl], "/exchange-keys" ]
			puts "Authorization: %s" % @config[:auth_string]
		end

		# Test Authentication
		begin
			res = RestClient.get( @config[:apiurl] + "/exchange-keys", { "Authorization" => @config[:auth_string]} )
		rescue => e
			puts "%s: %s" % [ e.result, e.response ]
		end
		#res = RestClient::Request.execute(
		#	method:	:get,
		#	url:		@config[:apiurl] + "/",
		#	headers:	{ "Authorization" => @config[:auth_string] }
		#)

		# Test for Failure and raise exception
		if res.code == 401
			raise "Cryptomnio Basic Authentication for user %s failed." % @config[:username]
			return false
		end

		# Success
		puts JSON.parse(res) if DEBUG
		return true
	end

	def upload_api_keys
		# Upload and store exchange API key(s) provided in config
		for cred in @config[:apikeys] do
			payload = {}
			payload["exchange"]   = cred[:exchange]
			payload["key"]        = cred[:key]
			payload["secret"]     = cred[:secret]
			payload["passphrase"] = cred[:passphrase] if cred[:passphrase]
			payload["clientid"]   = cred[:clientid]   if cred[:clientid]

			self.upload_api_key payload
		end
		return true
	end

	def upload_api_key( payload ) 
		# Upload and store a single exchange API key provided as a hash argument
		puts "POST %s/exchange-keys" % @config[:apiurl] if DEBUG
		puts JSON.generate(payload) if DEBUG

		RestClient.post( @config[:apiurl]+"/exchange-keys", JSON.generate(payload), { "Authorization" => @config[:auth_string], "Content-type" => "application/json" } ) do
			|response, request, result, &block|

			puts "%d: %s" % [ response.code, response ] if DEBUG
			reshash = JSON.parse(response)

			case response.code
			when !200
				raise "Cryptomnio Exchange Key for exchange %s storage failed." % payload["exchange"]
			else
				raise "Cryptomnio Exchange Key for exchange %s storage failed." % payload["exchange"] if reshash["code"] != "OK"
			end

			return true
		end
	end

	# Delete all exchange API keys from Cryptomnio
	def delete_api_keys
		# Get list of stored exchange API keys
		keylist = self.get_all_exchange_keys

		keylist["data"].each do | key |
			self.delete_api_key key
		end

	end

	def delete_api_key( key )
		# Delete a single exchange API key by key ID
		puts "Deleting key %d for exchange %s" % [ key["keyId"], key["exchange"] ] if DEBUG

		RestClient.delete( @config[:apiurl] + "/exchange-keys?keyId=" + key["keyId"] +"&exchange=" + key["exchange"], { "Authorization" => @config[:auth_string]} ) do
			|response, request, result, &block|
			puts "%d: %s" % [ response.code, response ] if DEBUG
			self._check_errors( response, "Deletion of Cryptomnio stored Exchange Key id %d failed." % key["keyId"] )

			# Success
			puts response if DEBUG
			return true
		end
	end

	# Return list hash of all stored exchange keys
	def get_all_exchange_keys
		RestClient.get( @config[:apiurl] + "/exchange-keys", { "Authorization" => @config[:auth_string]} ) do
			|response, request, result, &block|
			puts "%d: %s" % [ response.code, response ] if DEBUG
			self._check_errors( response, "Retrieval of Cryptomnio stored Exchange Keys failed." )

			# Success
			puts response if DEBUG
			# Return hash of all stored keys
			keylist = JSON.parse(response)["data"]
			puts keylist.inspect
			return keylist
		end
	end

	def order_create( key, side, order_type, pair, volume, price = nil )
		# Build Order Payload
		payload = {}
		payload["exchange"]  = key["exchange"]
		payload["keyId"]     = key["keyId"]
		payload["orderType"] = order_type
		payload["price"]     = price.to_s      if price
		payload["side"]      = side
		payload["volume"]    = volume.to_s
		payload["pair"]      = pair

		uri = "%s/order" % @config[:apiurl]
		puts "POST %s" % uri if DEBUG
		puts JSON.generate(payload) if DEBUG

		RestClient.post( uri, JSON.generate(payload), { "Authorization" => @config[:auth_string], "Content-type" => "application/json" } ) do
			|response, request, result, &block|
			puts "%d: %s" % [ response.code, response ] if DEBUG
			self._check_errors( response, "Cryptomnio Exchange order for exchange %s failed." % payload["exchange"] )

			reshash = JSON.parse(response)

			# Success
			puts response if DEBUG
			puts reshash.inspect if DEBUG
			# Return Cryptomnio Order ID
			return reshash["data"].to_i
		end
	end

	def order_get( key, order_id )
		uri = "%s/order?exchange=%s&keyId=%s&internalOrderId=%d" % [ @config[:apiurl], key["exchange"], key["keyId"], order_id ]
		puts "GET %s" % uri if DEBUG

		RestClient.get( uri, { "Authorization" => @config[:auth_string], "Content-type" => "application/json" } ) do
			|response, request, result, &block|
			puts "%d: %s" % [ response.code, response ] if DEBUG
			self._check_errors( response, "Retrieval of Cryptomnio order information for %d failed." % order_id )

			# Success
			order_info = JSON.parse(response)["data"]
			puts order_info.inspect if DEBUG
			# Return Order Info Hash
			return order_info
		end
	end

	def order_cancel( key, order_id )
		uri = "%s/order?exchange=%s&keyId=%s&internalOrderId=%d" % [ @config[:apiurl], key["exchange"], key["keyId"], order_id ]
		puts "DELETE %s" % uri if DEBUG

		RestClient.delete( uri, { "Authorization" => @config[:auth_string], "Content-type" => "application/json" } ) do
			|response, request, result, &block|

			puts "%d: %s" % [ response.code, response ] if DEBUG

			self._check_errors( response, "Deletion of Cryptomnio order %d failed." % order_id )

			# Success
			return true
		end
	end

	def orders_active_get( key )
		uri = "%s/orders/active?exchange=%s&keyId=%s" % [ @config[:apiurl], key["exchange"], key["keyId"] ]
		puts "GET %s" % uri if DEBUG

		RestClient.get( uri, { "Authorization" => @config[:auth_string], "Content-type" => "application/json" } ) do
			|response, request, result, &block|
			puts "%d: %s" % [ response.code, response ] if DEBUG
			self._check_errors( response, "Retrieval of Cryptomnio active orders information failed." )

			# Success
			orders_info = JSON.parse(response)["data"]
#			puts JSON.pretty_generate(orders_info)
			puts orders_info.inspect if DEBUG
			# Return Orders Info Hash
			return orders_info
		end
	end

	def orders_history_get( key )
		uri = "%s/orders/history?exchange=%s&keyId=%s" % [ @config[:apiurl], key["exchange"], key["keyId"] ]
		puts "GET %s" % uri if DEBUG

		RestClient.get( uri, { "Authorization" => @config[:auth_string], "Content-type" => "application/json" } ) do
			|response, request, result, &block|
			puts "%d: %s" % [ response.code, response ] if DEBUG
			self._check_errors( response, "Retrieval of Cryptomnio closed orders information failed." )

			# Success
			orders_info = JSON.parse(response)["data"]
#			puts JSON.pretty_generate(orders_info)
			puts orders_info.inspect if DEBUG
			# Return Orders Info Hash
			return orders_info
		end
	end

	def wallet_get( key )
		uri = "%s/wallet?exchange=%s&keyId=%s" % [ @config[:apiurl], key["exchange"], key["keyId"] ]
		puts "GET %s" % uri if DEBUG

		RestClient.get( uri, { "Authorization" => @config[:auth_string], "Content-type" => "application/json" } ) do
			|response, request, result, &block|
			puts "%d: %s" % [ response.code, response ] if DEBUG
			self._check_errors( response, "Retrieval of Cryptomnio wallet information for key %d failed." % key["keyId"])

			# Success
			balances = JSON.parse(response)["data"]["balances"]
			puts balances.inspect if DEBUG
			# Return Wallet Info hash of hashes
			wallet_info = {}
			balances.each do |currency|
				wallet_info[currency["currency"]] = currency
			end
			puts wallet_info.inspect if DEBUG
			return wallet_info
		end
	end

#	def wallet_get( key, exchange )
#		wallets = self.wallet_get_all( key )
#		wallets.each do |ex|
#			return ex["balances"] if ex["exchange"] == exchange
#		end
#		# Requested wallet not found
#		return nil
#	end



	def initialize
		yield self if block_given?
		super

		# Store method config variables in an instance variable
		p @config if DEBUG
	end

	def _check_errors( response, thisfailure )
		case response.code
		when 400
			raise "Error: [%d]: %s" % [ response.code, response ] 
			return false
		when 401
			raise "Cryptomnio Basic Authentication for user %s failed: [%d]: %s" % [ @config[:username], response.code, response ] 
			return false
		when !200
			raise thisfailure
			return false
		else
			# Success!
			return true
		end
	end

end
