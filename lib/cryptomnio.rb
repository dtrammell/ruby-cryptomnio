require 'rest-client'
require 'base64'
require 'json'

##
# This is the root Cryptomnio object Class.  It contains global constants.

class Cryptomnio
	attr_reader   :VERSION
	attr_reader   :API_VERSION

	# Creates a new Cryptomnio object
	def initialize
		##
		# Class Instance Variables

		# The name of the Gem
		@NAME        = "Cryptomnio Ruby Gem"
		# The name of the Gem's Author
		@AUTHOR      = "Dustin D. Trammell"
		# The publication date of the current Gem version
		@DATE        = "2020-08-29"
		# The Gem version
		@VERSION     = "0.1.0"
		# The Cryptomnio API Version
		@API_VERSION = "0.1.0"
		# API URI Path Version Slug @URI_VERSION = "/v1"
		@URI_VERSION = ""

		puts "Cryptomnio Initalized" if $DEBUG
	end

	# Returns the Gem information
	def geminfo
		info  = @NAME + " "   + @VERSION + "\n"
		info << @DATE + " - " + @AUTHOR  + "\n"
		info << "Cryptomnio API Version: " + @VERSION + "\n"

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
		# Call Superlcass initialize
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

	# Switch Object's Context (Account + Venue to operate as)
	def context_switch( label )
		puts "Switching to context \"%s\"" % label if $DEBUG

		# Validate that a context for label exists
		raise "No context found for label: %s" % label if ! @config[:contexts][label]
		puts @config[:contexts][label].inspect if $DEBUG

		# Validate that the required parameters exist
		raise "Missing Configuration Parameter: contexts[:venue]"      if ! @config[:contexts][label][:venue]
		raise "Missing Configuration Parameter: contexts[:accountid]"  if ! @config[:contexts][label][:accountid]
		raise "Missing Configuration Parameter: contexts[:venuekeyid]" if ! @config[:contexts][label][:venuekeyid]

		# Switch to the context
		@context = @config[:contexts][label]

		# Return true on success
		puts "Context Switch Successful!" if $DEBUG
		return true
	end

	# Cryptomnio Key Authentication
	def auth_cryptomnio( method, uripath )
		puts "Building Authentication Credentials" if $DEBUG

		# Create concatenated method and base URL path string
		methodpath = method.to_s.upcase + uripath # convert RestClient's method symbol to uppercase string
		puts "	Method+Path = %s" % methodpath if $DEBUG

		# Create HMAC SHA-512 authentication hash of methodpath using secret key
		@config[:auth_string] = Base64.encode64(OpenSSL::HMAC.digest('sha512', @config[:secret_key], methodpath)).split.join # .split.join is to remove '/n' inserted into signature by HMAC

		# Output
		if $DEBUG && $VERBOSE
			puts "	Access-Key: %s" % @config[:access_key]
			puts "	Signature:  %s" % @config[:auth_string]
			puts
		end

		# Return the signature
		return @config[:auth_string]
	end

	# Test method wrapper for Cryptomnio Key Authentication
	def auth_cryptomnio_test
		# TODO: Find better CMA test call to use
		method   = :get 
		endpoint = "/venues"
		#endpoint = "/nope"
		uripath  = @URI_VERSION + endpoint
		signature = self.auth_cryptomnio( method, uripath )

		puts "Testing Cryptomnio Key Authentication" if $VERBOSE
		if $DEBUG
			puts "	Requesting: %s %s%s" % [ method, @config[:apiurl], uripath ]
			puts "	Access-Key: %s"      % @config[:access_key]
			puts "	Signature:  %s"      % signature
		end

		# Test Authentication Call
		self._rest_call( method, api = :core, uripath = uripath, uriparameters = nil, error_string = "Cryptomnio Key Authentication test failed." )

		# Success
		return true
	end

	# Generic REST API call method
	# Provides RestClient call with needed authentication headers and error handling
	def _rest_call( method = :get, api = :core, uripath = "/", uriparameters = nil, error_string = "REST API Call Failed", body = nil )
		# Get the HMAC SHA-512 hash signature value for the method+URIpath
		signature = self.auth_cryptomnio( method, @URI_VERSION + uripath )

		# Build the URI from the URIpath and optional parameters
		case api
			when :core
				uri = "https://" + @config[:api_host_core] + @URI_VERSION + uripath
			when :cma
				uri = "https://" + @config[:api_host_cma] + @URI_VERSION + uripath
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
		begin
			RestClient::Request.execute(
				method:  method,
				url:     uri,
				headers: headers,
				payload: body
				) do
				|response, request, result, &block|

				# Verbose output
				if $DEBUG
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
						#pp responsebody if $DEBUG
						return responsebody 
					when :cma
						responsebody = JSON.parse(response)
						#pp responsebody if $DEBUG
						return responsebody 
					else
						raise "Unknown API (%s) referenced" % api
				end
			end
		rescue => e
			# Rescue any exceptions thrown by _check_errors

			# TODO: Retry 3 times with pauses if temporary error
			
			# Output
			puts e.inspect if $DEBUG
			puts e.message if $DEBUG

			# Pass it on
			raise e
		end
	end

   ##
	# CORE API Venue and Market function methods

	# Return an array of supported Venues
	def get_venues
		return self._rest_call( :get, :core, "/venues", nil, "Retrieval of supported venues failed." )
	end

	# Return an array of hashes of a venue's markets
	def get_markets( venue )
		uripath = "/venues/" + venue + "/markets"
		return self._rest_call( :get, :core, uripath, nil, "Retrieval of supported venue's markets failed." )
	end

   ##
	# CORE API Account function methods

	# Return a hash of a venue account
	def get_account(
		venue     = @context[:venue].to_s,
		accountid = @context[:accountid] )

		uripath   = "/venues/" + venue + "/accounts/" + accountid
		errormsg  =  "Retrieval of venue account information for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, nil, errormsg )
	end

	# Return an array of hashes of a venue account's balances 
	def get_account_balance(
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/balance"
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's balance for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Get account balance for symbol
	def get_account_balance_symbol(
		symbol,
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

		symbol = symbol.downcase
		$balance = nil
		# TODO: Check cached balance's timestamp, if too old, update balances
		# Retrieve all balances for account
		@balances = self.get_account_balance( venue, accountid, venuekeyid )
		# Find the balance for the symbol we want
		@balances["assets"].each do |asset|
			$balance = asset["amount"] if asset["currency"] == symbol
		end
		# Raise an exception if the requested symbol is not found
		raise "No balance returned for currency symbol \"%s\"" % symbol if ! $balance
		# Return balance for requested symbol as a floating-point integer
		return $balance.to_f
	end

	# Return an array of hashes of a venue account's orders
	# Accepts optional array of orders statuses for filtering results
	def get_account_orders(
		status_filters = [],
		venue          = @context[:venue].to_s,
		accountid      = @context[:accountid],
		venuekeyid     = @context[:venuekeyid] )

		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders"
		uriparams = "venueKeyId=" + venuekeyid 
		status_filters.each do |status|
			uriparams << "&status=" + status.to_s
		end
		errormsg  = "Retrieval of venue account's orders for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Return an hash of a venue account's single order
	def get_account_order(
		orderid,
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders/" + orderid
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's order %s for account %s failed." % [orderid, accountid]
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Create a new market order under a venue account
	def put_account_order_market(
		side,
		quantity,
		market,
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

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
	def put_account_order_limit( 
		side,
		quantity,
		price,
		market,
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

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
	def del_account_order(
		orderid,
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/orders/" + orderid
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Cancellation of venue account's order %s for account %s failed." % [orderid, accountid]
		return self._rest_call( :delete, :core, uripath, uriparams, errormsg )
	end

	# Return an array of hashes of a venue account's trades
	def get_account_trades(
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/trades"
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's orders for account %s failed." % accountid
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	# Return a hashe of a venue account's trade
	def get_account_trade(
		tradeid,
		venue      = @context[:venue].to_s,
		accountid  = @context[:accountid],
		venuekeyid = @context[:venuekeyid] )

		uripath   = "/venues/exchanges/" + venue + "/accounts/" + accountid + "/trades/" + tradeid
		uriparams = "venueKeyId=" + venuekeyid 
		errormsg  = "Retrieval of venue account's trade %s for account %s failed." % [tradeid, accountid]
		return self._rest_call( :get, :core, uripath, uriparams, errormsg )
	end

	##
	# CMA API Methods

	# Return a hash of a venue market's order book
	def get_market_orderbook(
		market,
		side  = nil,
		limit = nil,
		venue = @context[:venue].to_s)

		uripath   = "/venues/" + venue + "/markets/" + market + "/orderbook"
		uriparams = ""
		uriparams << "&side=%s"  % side  if side
		uriparams << "&limit=%d" % limit if limit
		uriparams = nil if uriparams.length == 0

		return self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's order book failed." )
	end

	# Return an array of a venue market's ticker hashes
	def get_market_tickers(
		market,
		from   = (Time.now - 60).to_i*1000, # last one minute in milliseconds
		to     = nil, # to defaults to Time.now within Cryptomnio
		cursor = nil,
		venue  = @context[:venue].to_s)

		uripath    = "/venues/" + venue + "/markets/" + market + "/ticker"
		uriparams  = "from=%s"    % from
		uriparams << "&to=%s"     % to     if to
		uriparams << "&cursor=%d" % cursor if cursor

		retries = 0
		begin
			result = self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's market ticker failed." )
			raise "Error: Empty set of tickers received" if result['tickers'].count < 1
			return result
		rescue => e
			case
				when retries <= 3
					retries += 1
					sleep 1
					retry
				else
					raise "Error: Received empty set of tickers for 3 retries: %s" % e.message
					return false
			end	
		end
	end

	# Return a venue market's most current ticker hash
	def get_market_ticker(
		market,
		venue  = @context[:venue].to_s)

		# Call get_market_tickers to request a single ticker (last 20 seconds)
		tickers = self.get_market_tickers( market, (Time.now.to_i - 20)*1000, nil, nil, venue ) 
		# Return the last ticker in the array (in case somehow we got back more than one)
		count = tickers['tickers'].count

		# Output
		puts "Ticker: %s" % tickers['tickers'][count - 1] if $DEBUG

		# Return the most recent ticker from the array
		return tickers['tickers'][count - 1]
	end

	# Return a venue market's recent trades array
	def get_market_trades(
		market,
		limit = nil,
		venue = @context[:venue].to_s )

		uripath   = "/venues/"  + venue + "/markets/" + market + "/trades"
		uriparams = "&limit=%s" % limit if limit

		retries = 0
		begin
			result = self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's market ticker failed." )

			# Raise an execption if the result is null or empty
			raise "Error: Empty set of market trades received" if ! result || result.count < 1

			# Output
			if $DEBUG
				puts "Trades:\n"
				pp result
			end

			# Return the trades array
			return result
		rescue => e
			case
				when retries <= 3
					retries += 1
					sleep 1
					retry
				else
					raise "Error: Received empty set of market trades for 3 retries: %s" % e.message
					return false
			end	
		end

	end

	# Return an array of period data
	def get_market_periods(
		market,
		periodlength,
		periodcount   = nil, # periodCount defaults to 10 within Cryptomnio
		to            = nil, # to defaults to Time.now within Cryptomnio
		limit         = nil,
		venue         = @context[:venue].to_s)

		uripath    = "/venues/" + venue + "/markets/" + market + "/periods"
		uriparams  = "periodLength=%s" % periodlength
		uriparams << "&periodCount=%d" % periodcount  if periodcount
		uriparams << "&to=%d"          % to           if to
		uriparams << "&limit=%d"       % limit        if limit

		# TODO: Determine if we have any of the requested periods cached, and instead request only what we don't already have

		retries = 0
		begin
			result = self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's market periods failed." )
			
			# Raise an execption if the result is null or empty
			raise "Error: Empty set of market periods received" if ! result || result.count < 1
			
			# Output
			if $DEBUG
				puts "Periods:\n"
				pp result
			end

			# Return the periods array
			return result
		rescue => e
			case
				when retries <= 3
					retries += 1
					sleep 1
					retry
				else
					raise "Error: Received empty set of market periods for 3 retries: %s" % e.message
					return false
			end	
		end
	end

	# Return a momentum value for a defined period of time
	def get_market_momentum(
		market,
		type,
		periodlength,
		periodcount   = nil, # periodCount defaults to 10 within Cryptomnio
		to            = nil, # to defaults to Time.now within Cryptomnio
		venue         = @context[:venue].to_s)

		uripath    = "/venues/" + venue + "/markets/" + market + "/momentum"
		uriparams  = "type=%s"          % type
		uriparams << "&periodLength=%s" % periodlength
		uriparams << "&periodCount=%d"  % periodcount  if periodcount
		uriparams << "&to=%d"           % to           if to

		retries = 0
		begin
			result = self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's market momentum failed." )
			
			# Raise an execption if the result is null or empty
			raise "Error: Empty set of market momentum received" if ! result || result.count < 1
			
			# Output
			puts "Momentum: %f\n" % result['price_change'].to_f if $DEBUG

			# Return momentum value
			return result['price_change'].to_f
		rescue => e
			case
				when retries <= 3
					retries += 1
					sleep 1
					retry
				else
					raise "Error: Received empty set of market momentum for 3 retries: %s" % e.message
					return false
			end	
		end
	end

	# Return an exponential moving average value for a defined period of time
	def get_market_ema(
		market,
		type,
		periodlength,
		periodcalc,
		periodcount   = nil, # periodCount defaults to 10 within Cryptomnio
		to            = nil, # to defaults to Time.now within Cryptomnio
		venue         = @context[:venue].to_s)

		uripath    = "/venues/" + venue + "/markets/" + market + "/averages/ema"
		uriparams  = "type=%s"          % type
		uriparams << "&periodLength=%s" % periodlength
		uriparams << "&periodCalc=%d"   % periodcalc
		uriparams << "&periodCount=%d"  % periodcount   if periodcount
		uriparams << "&to=%d"           % to            if to

		retries = 0
		begin
			result = self._rest_call( :get, :cma, uripath, uriparams, "Retrieval of venue's market's market Exponential Moving Average (EMA) failed." )
			
			# Raise an execption if the result is null or empty
			raise "Error: Empty set of market Exponential Moving Average (EMA) received" if ! result || result.count < 1
			
			# Output
			if $DEBUG
				puts "EMA sets:\n"
				pp result
			end

			# Return averages array
			return result
		rescue => e
			case
				when retries <= 3
					retries += 1
					sleep 1
					retry
				else
					raise "Error: Received empty set of market Exponential Moving Average (EMA) for 3 retries: %s" % e.message
					return false
			end	
		end

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
			when 'Basic'
				raise "Missing Configuration Parameter: username"   if ! @config[:username]
				raise "Missing Configuration Parameter: password"   if ! @config[:password]
			when 'Cryptomnio'
				raise "Missing Configuration Parameter: access_key" if ! @config[:access_key]
				raise "Missing Configuration Parameter: secret_key" if ! @config[:secret_key]
			else
				raise "Unrecognized Authentication Type: %s" % @config[:authtype]
		end

		# Check for at least one contexts (venue+account)
		raise "Missing Configuration Paramters: contexts"         if @config[:contexts].count < 1

		# Check configured contexts and validate them by switching to them
		puts "Checking all configured contexts (venue + account) for required parameters" if $DEBUG
		@config[:contexts].each do | label, paramhash |
			self.context_switch( label )
		end

		# Switch back to the first context by default
		puts "Switching back to the first context by default" if $DEBUG
		label = @config[:contexts].keys[0]
		self.context_switch( label )

		# Output
		if $DEBUG
			puts "Cryptomnio Startup Configuration:"
			p @config
		end
	end

	##
	# Utility Methods

	# Error-handling method
	def _check_errors( response, thisfailure )
		case
		when response.code == 400
			raise "Error: [%d]: %s" % [ response.code, response ] 
			return false
		when response.code == 401
			case @config[:authtype] 
			when "Basic"
				raise "Cryptomnio Basic Authentication for user %s failed: [%d]: %s" % [ @config[:username], response.code, response ]
				return false
			when "Cryptomnio"
				raise "Cryptomnio Key Authentication failed: [%d]: %s" % [ response.code, response ]
				return false
			else
				raise "Authentication failed: [%d]: %s" % [ response.code, response ]
				return false
			end
		when response.code == 404
			raise "Error: Missing Resource"
			return false
		when response.code == 502
			# Bad Gateway
			raise "Error: %s: [%d]: %s" % [ thisfailure, response.code, response ]
		when response.code == 504
			# Gateway Timeout (temporary error)
			raise "Temporary Error: %s: [%d]: %s" % [ thisfailure, response.code, response ] 
			return false
		when response.code != 200
			# Catch-all: Anything other than success
			raise "Error: %s: [%d]: %s" % [ thisfailure, response.code, response ] 
			return false
		else
			# 200 Success!
			return true
		end
	end

end
