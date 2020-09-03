require 'rest-client'
require 'base64'
require 'json'

##
# This is the root Cryptomnio object Class.  It contains global constants.

class Cryptomnio
	# The name of the Gem
	NAME        = "Cryptomnio Ruby Gem"
	# The name of the Gem's Author
	AUTHOR      = "Dustin D. Trammell"
	# The publication date of the current Gem version
	DATE        = "2020-08-29"
	# The Gem version
	GEM_VERSION = "0.0.2.pre"
	# The Cryptomnio API Version
	API_VERSION = "1.0.0"
	#URI_VERSION = "/v1"
	URI_VERSION = ""

	# Instance Variables

	##
	# Creates a new Cryptomnio object

	def initalize
		puts "Cryptomnio Initalized" if VERBOSITY >= 1
	end

	def geminfo
		info = NAME + " " + GEM_VERSION + "\n"
		info << DATE + " - " + AUTHOR + "\n"
		info << "Cryptomnio API Version: " + API_VERSION + "\n"

		return info
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
		RestClient.proxy = ENV['http_proxy'] if ENV['http_proxy']
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

		# Output
		if VERBOSITY >= 2
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
		puts JSON.parse(res) if VERBOSITY >= 2
		return true
	end

	# Cryptomnio Key Authentication
	def auth_cryptomnio( method, uripath )
		puts "Building Authentication Credentials" if VERBOSITY >= 1

		# Create concatenated method and base URL path string
		methodpath = method.to_s.upcase + uripath # convert RestClient's method symbol to uppercase string
		puts "	Method+Path = %s" % methodpath if VERBOSITY >= 2

		# Create HMAC SHA-512 authentication hash of methodpath using secret key
		@config[:auth_string] = Base64.encode64(OpenSSL::HMAC.digest('sha512', @config[:secret_key], methodpath)).split.join # .split.join is to remove '/n' inserted into signature by HMAC

		# Output
		if VERBOSITY >= 2
			puts "	Access-Key: %s" % @config[:access_key]
			puts "	Signature:  %s" % @config[:auth_string]
			puts
		end

		return @config[:auth_string]
	end

	# Test method wrapper for Cryptomnio Key Authentication
	def auth_cryptomnio_test
		# TODO: Find better CMA test call to use
		method   = :get 
		endpoint = "/venues"
		#endpoint = "/nope"
		uripath  = URI_VERSION + endpoint
		signature = self.auth_cryptomnio( method, uripath )

		puts "Testing Cryptomnio Key authentication" if VERBOSITY >= 1
		if VERBOSITY >= 2
			puts "	Requesting: %s %s%s" % [ method, @config[:apiurl], uripath ]
			puts "	Access-Key: %s"      % @config[:access_key]
			puts "	Signature:  %s"      % signature
		end

		# Test Authentication Call
		self._rest_call( method, uripath, nil, "Cryptomnio Key Authentication test failed." )

		# Success
		return true
	end

	# Generic REST API call method
	# Provides RestClient call with needed authentication headers and error handling
	def _rest_call( method = :get, api = :core, uripath = "/", uriparameters = nil, error_string = "REST API Call Failed", body = nil )
		# Get the HMAC SHA-512 hash signature value for the method+URIpath
		signature = self.auth_cryptomnio( method, URI_VERSION + uripath )

		# Build the URI from the URIpath and optional parameters
		case api
			when :core
				uri = "https://" + @config[:api_host_core] + URI_VERSION + uripath
			when :cma
				uri = "https://" + @config[:api_host_cma] + URI_VERSION + uripath
			else
				raise "Unknown API (%s) referenced" % api
		end
		uri << "?" + uriparameters if uriparameters

		##
		# Build the Headers

		headers = {
			# Authentication headers Access-Key and Sign
			"Access-Key" => @config[:access_key],
			"Sign"       => signature
		}
		# Add a Content-type header for application/json if there is a payload body to send
		headers["Content-type"] = "application/json" if body

		# Call RestClient based on the method against URI with authentication headers "Access-Key" and "Sign"
		RestClient::Request.execute(
			method:  method,
			url:     uri,
			headers: headers,
			payload: body
			) do
			|response, request, result, &block|

			# Verbose output
			if VERBOSITY >= 3
				puts "Request:      %s: %s" % [ request.method.upcase, request.uri ]
				puts "Headers:      %s"     % [ request.headers ]
				puts "POST payload: %s"     % [ body ] if body
				puts "Response:     %d: %s" % [ response.code, response ]
			end

			# Check for errors
			self._check_errors( response, error_string )

			# Success: Convert JSON to Ruby object and return it
			# TODO: remove this workaround that handles the two APIs differently once they are consistent
			case api
				when :core
					responsebody = JSON.parse(response)["body"]
					pp responsebody if VERBOSITY >= 2 
					return responsebody 
				when :cma
					responsebody = JSON.parse(response)
					pp responsebody if VERBOSITY >= 2 
					return responsebody 
				else
					raise "Unknown API (%s) referenced" % api
			end
		end
	end

   ##
	# CORE API Venue and Market function methods

	# Return an array of supported Venues
	def retrieve_venues
		return self._rest_call( :get, :core, "/venues", nil, "Retrieval of supported venues failed." )
	end

	# Return an array of hashes of a venue's markets
	def retrieve_venue_markets( venue )
		uripath = "/venues/" + venue + "/markets"
		return self._rest_call( :get, :core, uripath, nil, "Retrieval of supported venue's markets failed." )
	end

   ##
	# CORE API Account function methods

	# Return a hash of a venue account
	def retrieve_venue_account( venue, accountid )
		uripath   = "/venues/" + venue + "/accounts/" + accountid
		errormsg  =  "Retrieval of venue account information for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, nil, errormsg )
	end

	# Return an array of hashes of a venue account's balances 
	def retrieve_venue_account_balance( venue, accountid, venuekeyid )
		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/balance"
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's balance for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Get account balance for symbol
	def retrieve_venue_account_balance_symbol( venue, accountid, venuekeyid, symbol )
		@balance = nil
		# TODO: Check timestamp, if too old, update balances
		@balances = self.retrieve_venue_account_balance( venue, accountid, venuekeyid )
		pp @balances if VERBOSITY >= 2
		@balances["assets"].each do |asset|
			@balance = asset["amount"] if asset["currency"] == symbol.downcase
		end
		return @balance
	end

	# Return an array of hashes of a venue account's orders
	# Accepts optional parameters for orders statuses for filtering results
	def retrieve_venue_account_orders( venue, accountid, venuekeyid, *statuses )
		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders"
		uriparams = "venueKeyId=" + venuekeyid 
		statuses.each do |status|
			uriparams << "&status=" + status.to_s
		end
		errormsg  = "Retrieval of venue account's orders for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Return an hash of a venue account's single order
	def retrieve_venue_account_order( venue, accountid, venuekeyid, orderid )
		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders/" + orderid
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's order %s for account %s failed." % [orderid, accountid]
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Create a new market order under a venue account
	def create_venue_account_order_market( venue, accountid, venuekeyid, side, quantity, market )
		uripath  = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders"
		errormsg = "Creation of new market order for account %s failed." % accountid
		body     = {
			"venue"      => venue,
			"venueKeyId" => venuekeyid,
			"orderType"  => "market",
			"side"       => side,
			"quantity"   => quantity,
			"market"     => market
		}
		return self._rest_call( :post, :core, uripath, nil, errormsg, body.to_json )
	end

	# Create a new limit order under a venue account
	def create_venue_account_order_limit( venue, accountid, venuekeyid, side, quantity, price, market )
		uripath  = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders"
		errormsg = "Creation of new limit order for account %s failed." % accountid
		body     = {
			"venue"      => venue,
			"venueKeyId" => venuekeyid,
			"orderType"  => "limit",
			"side"       => side,
			"quantity"   => quantity,
			"price"      => price,
			"market"     => market
		}
		return self._rest_call( :post, :core, uripath, nil, errormsg, body.to_json )
	end

	# Delete (cancel) a venue account's open order
	def delete_venue_account_order( venue, accountid, venuekeyid, orderid )
		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders/" + orderid
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Cancellation of venue account's order %s for account %s failed." % [orderid, accountid]
		return self._rest_call( :delete, :core, uripath, uriparams, errormsg )
	end

	# Return an array of hashes of a venue account's trades
	def retrieve_venue_account_trades( venue, accountid, venuekeyid )
		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/trades"
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's orders for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Return a hashe of a venue account's trade
	def retrieve_venue_account_trade( venue, accountid, venuekeyid, tradeid )
		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/trades/" + tradeid
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's trade %s for account %s failed." % [tradeid, accountid]
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	##
	# CMA API Methods

	# Return a hash of a venue market's order book
	def retrieve_venue_market_orderbook( venue, market, side = nil, limit = nil )
		uripath   = "/venues/" + venue + "/markets/" + market + "/orderbook"
		uriparams = ""
		uriparams << "&side=" + side if side
		uriparams << "&limit=" + limit if limit
		uriparams = nil if uriparams.length == 0
		return self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's order book failed." )
	end

	# Return an array of a venue market's ticker hashes
	def retrieve_venue_market_tickers( venue, market, from = (Time.now - 60).to_i, to = nil, cursor = nil )
		uripath    = "/venues/"  + venue + "/markets/" + market + "/ticker"
		uriparams  = "from=%s"  % from
		uriparams << "&to=%s"   % to     if to
		uriparams << "&cursor=" + cursor if cursor
		return self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's market ticker failed." )
	end

	# Return a venue market's most current ticker hash
	def retrieve_venue_market_ticker( venue, market )
		tickers = self.retrieve_venue_market_tickers( venue, market ) 
		count =  tickers['tickers'].count
		if VERBOSITY >= 2
			puts "Found %d tickers" % count
			puts "Index 0: %s" % tickers['tickers'][0].inspect
			puts "Index %d: %s" % [ count - 1, tickers['tickers'][count - 1].inspect ]
			puts "Cursor: %d" % tickers['cursor']
		end
		return tickers['tickers'][count - 1]
	end

	##
	# Object Methods

	# Object initialization
	def initialize
		yield self if block_given?
		super

		##
		# Configuration check

		# Check for required API hostnames
		raise "Missing Configuration Parameter: api_host_core"    if ! @config[:api_host_core]
		raise "Missing Configuration Parameter: api_host_cma"     if ! @config[:api_host_cma]
		# Check for required Authentication Credentials
		raise "Missing Configuration Parameter: authtype"         if ! @config[:authtype]
		case @config[:authtype]
			when "Basic"
				raise "Missing Configuration Parameter: username"   if ! @config[:username]
				raise "Missing Configuration Parameter: password"   if ! @config[:password]
			when "Cryptomnio:"
				raise "Missing Configuration Parameter: access_key" if ! @config[:access_key]
				raise "Missing Configuration Parameter: secret_key" if ! @config[:secret_key]
			else
		end

		# Store method config variables in an instance variable
		if VERBOSITY >= 1
			puts "Configuration:"
			p @config
		end
	end

	##
	# Utility Methods

	# Error-handling method
	def _check_errors( response, thisfailure )
		case response.code
		when 400
			raise "Error: [%d]: %s" % [ response.code, response ] 
			return false
		when 401
			case @config[:authtype] 
			when "Basic"
				raise "Cryptomnio Basic Authentication for user %s failed: [%d]: %s" % [ @config[:username], response.code, response ]
				return false
			when "Cryptomnio"
				raise "Cryptomnio Key Authentication failed: [%d]: %s" % [ response.code, response ]
				return false
			else
				raise "Authentication failed: [%d]: %s" % [ response.code, response ]
			end
		when 404
			raise "Error: Missing Resource"
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
